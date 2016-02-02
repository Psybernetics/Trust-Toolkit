# _*_ coding: utf-8 _*_
"""
The system depends on good peers. EigenTrust++ works optimally when it has
pre-trusted peers to defer to.

If your test case does something like render all peers unlikeable you may want
to set your good peers up with some pre-trusted peers.
"""
import utils
import random

def scenario_one(options):
    """
    Pre-trusted and malicious peers with at least 10 neighbours.
    Good peers with at least 2 neighbours.
    """
    routers      = utils.generate_routers(options, minimum=10)
    good_routers = routers[:2]
    bad_routers  = routers[2:]

    [setattr(_, "probably_malicious", True) for _ in bad_routers]

    utils.introduce(good_routers)
    [_.tbucket.append(_.peers[:options.pre_trusted]) for _ in good_routers]

    utils.introduce(bad_routers)
    utils.introduce(good_routers, random.sample(bad_routers, 2))

    for router in routers:    
        for peer in router:
            [router.transact_with(peer) for _ in range(random.randint(0,10))]

    good_routers[0].tbucket.calculate_trust()

    # The return value of a scenario is used to populate "locals" in the event
    # that you choose to use the --repl flag to spawn an interactive interpreter.
    return {"routers": routers}

def threat_model_a(options):
    """
    Independently malicious peers who're not initially aware of eachother.
    """
    routers = utils.generate_routers(options, minimum=10)
    [setattr(r, "probably_malicious", True) for r in routers]
    good_peer = utils.Router()
    
    [r.routers.append(good_peer) for r in routers]
    good_peer.routers = routers
    utils.introduce(good_peer, random.sample(routers, options.nodes / 2))

    utils.log("Emulating %s iterations of transactions with all peers." % \
        "{:,}".format(options.transactions))
    for _ in range(options.transactions):
        [good_peer.transact_with(peer) for peer in good_peer.peers]
    
        for router in routers:
            [router.transact_with(peer) for peer in router.peers]

    good_peer.tbucket.calculate_trust()

    routers.insert(0, good_peer)
    return {"routers": routers}

def threat_model_b(options):
    """
    Chain of Malicious Collectives who know eachother upfront and
    deterministically give a high trust value to another malicious peer.
    Resembles a malicious chain of mutual high local trust values.
    """
    class EvilRouter(utils.Router):

        def __init__(self):
            utils.Router.__init__(self)
            self.probably_malicious = True

        def render_peers(self):
            response = []
            for peer in self.peers:
                data = peer.jsonify()
                if any(filter(lambda r: r.node == peer, self.collective)):
                    data['trust'] = data['trust'] * 2
                response.append(data)
            return response
    
    routers    = utils.generate_routers(options, minimum=7, router_class=EvilRouter)
    good_peers = utils.generate_routers(options, minimum=3)

    [setattr(r, "collective", routers) for r in routers]

    all_routers = []
    all_routers.extend(good_peers)
    all_routers.extend(routers)

    [setattr(r, "routers", all_routers) for r in routers]
    [setattr(r, "routers", all_routers) for r in good_peers]

    utils.introduce(routers)
    utils.introduce(good_peers)
    
    # Set good peers up with some pre-trusted friends
    # NOTE: Routing tables don't fare well without trusted peers.
    [_.tbucket.append(_.peers[:options.pre_trusted]) for _ in good_peers]

    divisor = 1 if options.nodes == 1 else 2
    utils.introduce(good_peers, random.sample(routers, len(routers) / divisor))

    utils.log("Emulating %s iterations of transactions with all peers." % \
        "{:,}".format(options.transactions))
    for _ in range(options.transactions):
        for router in good_peers:
            for peer in router.peers:
                router.transact_with(peer)
 
        for router in routers:
            for peer in router.peers:
                router.transact_with(peer)

    good_peers[0].tbucket.calculate_trust()
    #[router.tbucket.calculate_trust() for router in good_peers]

    return {"routers": all_routers}

def threat_model_c(options):
    """
    Malicious Collectives with camouflage.
    Malicious peers try to earn high local trust from good peers by providing
    authentic services in f% of all cases.
    """
    class EvilRouter(utils.Router):
        def __init__(self):
            utils.Router.__init__(self)
            self.probably_malicious = True
            self.counter            = 0
            self.f                  = 0.2    # out of 1.0.
            self.responses          = [0, 0] # [negative, positive]

        @property
        def malicious(self):
            self.counter += 1
            if self.counter >= 100: self.counter = 0
            if self.counter <= max(int(100 * self.f), 1):
                self.responses[0] += 1
                return True
            self.responses[1] += 1
            return False

    bad_peers  = utils.generate_routers(options, minimum=10, router_class=EvilRouter)
    good_peers = utils.generate_routers(options, minimum=5)
    routers = []
    routers.extend(bad_peers)
    routers.extend(good_peers)
    [setattr(r, "routers", routers) for r in bad_peers]
    [setattr(r, "routers", routers) for r in good_peers]

    utils.introduce(good_peers)
    utils.introduce(bad_peers)
    
    # Configure pre-trusted peers
    [_.tbucket.append(_.peers[:options.pre_trusted]) for _ in good_peers]

    utils.introduce(good_peers, random.sample(bad_peers, options.nodes))

    transactions = max(options.transactions, 100)

    utils.log("Emulating %s transactions with each peer." % \
        "{:,}".format(transactions))
    for _ in range(transactions):
        for router in good_peers:
            [router.transact_with(peer) for peer in router.peers]
        for routers in bad_peers:
            [router.transact_with(peer) for peer in router.peers]

    good_peers[0].tbucket.calculate_trust()

    for router in bad_peers:
        utils.log("%s %i negative transactions, %i positive." % \
            (router, router.responses[0], router.responses[1]))
    
    return {"routers": routers}

def threat_model_d(options):
    """
    Malicious peers who are strategically organised into two groups.
    One group of peers act as normal peers and try to increase their global
    reputation by only providing good services and use the reputation they
    gain to boost the trust values of another group of malicious peers.
    """
    class AccompliceRouter(utils.Router):

        def render_peers(self):
            response = []
            for peer in self.peers:
                data = peer.jsonify()
                if any(filter(lambda r: r.node == peer, self.collective)):
                    data['trust'] = data['trust'] * 2
                response.append(data)
            return response

    class EvilRouter(utils.Router):

        def __init__(self):
            utils.Router.__init__(self)
            self.probably_malicious = True

        def render_peers(self):
            response = []
            for peer in self.peers:
                data = peer.jsonify()
                if any(filter(lambda r: r.node == peer, self.collective)):
                    data['trust'] = max(data['trust'], 0.5) * 2
                response.append(data)
            return response
    
    bad_peers        = utils.generate_routers(options, minimum=10, router_class=EvilRouter)
    accomplice_peers = utils.generate_routers(options, minimum=10, router_class=AccompliceRouter)
    good_peers       = utils.generate_routers(options, minimum=20)

    routers = []
    routers.extend(bad_peers)
    routers.extend(accomplice_peers)
    routers.extend(good_peers)

    [setattr(r, "collective", bad_peers) for r in bad_peers]
    [setattr(r, "collective", bad_peers) for r in accomplice_peers]

    [setattr(r, "routers", routers) for r in routers]

    utils.introduce(good_peers)

    # Set good peers up with some pre-trusted friends
    [_.tbucket.append(_.peers[:options.pre_trusted]) for _ in good_peers]

    utils.introduce(routers)

    utils.log("Emulating %s iterations of transactions with all peers." % \
        "{:,}".format(options.transactions))
    for _ in range(options.transactions):
        for router in good_peers:
            for peer in router.peers:
                router.transact_with(peer)

        # Accomplice routers work by doubling the trust trust rating of
        # peers in the collective, which necessitates some good transactions
        for router in routers:
            for peer in router.peers:
                router.transact_with(peer)

    good_peers[0].tbucket.calculate_trust()
    #[router.tbucket.calculate_trust() for router in good_peers]

    return {"routers": routers}

def threat_model_e(options):
    """
    Sybil attack. A hundred malicious peers who only provide bad services,
    who're then replaced with a new similarly malicious identity once contacted
    by good peers.
    """
    bad_peers  = utils.generate_routers(options, minimum=100)
    good_peers = utils.generate_routers(options, minimum=100)
    
    [setattr(r, "probably_malicious", True) for r in bad_peers]

    routers = []
    routers.extend(bad_peers)
    routers.extend(good_peers)

    [setattr(r, "routers", routers) for r in bad_peers]
    [setattr(r, "routers", routers) for r in good_peers]

    utils.introduce(bad_peers)
    utils.introduce(good_peers)

    # Set good peers up with some pre-trusted friends
    [_.tbucket.append(_.peers[:options.pre_trusted]) for _ in good_peers]

    divisor = 1 if options.nodes == 1 else 2
    utils.introduce(good_peers, random.sample(bad_peers, len(routers) / divisor))

    utils.log("Emulating %s iterations of transactions with all peers." % \
        "{:,}".format(options.transactions))
    for _ in range(options.transactions):
        for router in good_peers:
            for peer in router.peers:
        
                positive_transaction = router.transact_with(peer)
                
                if positive_transaction == False:
                    router.dereference(peer, and_router=True)
                    new_router = utils.Router()
                    new_router.probably_malicious = True
                    utils.introduce(router, new_router)

    good_peers[0].tbucket.calculate_trust()
    #[router.tbucket.calculate_trust() for router in good_peers]

    return {"routers": routers}

def threat_model_f(options):
    """
    Virus disseminating peers who send one inauthentic virus infected file every
    100th request.
    """
    class EvilRouter(utils.Router):
        def __init__(self):
            utils.Router.__init__(self)
            self.probably_malicious = True
            self.counter            = 0

        @property
        def malicious(self):
            self.counter += 1
            return not self.counter % 100

    bad_peers  = utils.generate_routers(options, minimum=10, router_class=EvilRouter)
    good_peers = utils.generate_routers(options, minimum=5)
    routers = []
    routers.extend(bad_peers)
    routers.extend(good_peers)
    [setattr(r, "routers", routers) for r in bad_peers]
    [setattr(r, "routers", routers) for r in good_peers]

    utils.introduce(good_peers)
    utils.introduce(bad_peers)
    
    # It's at this point that you want to set up your pre-trusted peers
    [_.tbucket.append(_.peers[:options.pre_trusted]) for _ in good_peers]

    # and then some not so trustworthy peers
    utils.introduce(good_peers, random.sample(bad_peers, options.nodes))

    # Since our EvilRouter only does its thing once every hundred transactions
    # we're going to define a minimum transaction count of 1,000 in this case.
    transactions = max(options.transactions, 1000)

    utils.log("Emulating %s transactions with each peer." % \
        "{:,}".format(transactions))
    for _ in range(transactions):
        for router in good_peers:
            [router.transact_with(peer) for peer in router.peers]
        for routers in bad_peers:
            [router.transact_with(peer) for peer in router.peers]

    good_peers[0].tbucket.calculate_trust()

    return {"routers": routers}

map = {
        "one": scenario_one,
        "A": threat_model_a,
        "B": threat_model_b,
        "C": threat_model_c,
        "D": threat_model_d,
        "E": threat_model_e,
        "F": threat_model_f
      }


# _*_ coding: utf-8 _*_
import utils
import random

def scenario_one(options):
    """
    Pre-trusted and malicious peers with at least 10 neighbours.
    Good peers with at least 2 neighbours.
    """
    routers = utils.generate_routers(options, minimum=10)
    good_routers = routers[:2]
    bad_routers  = routers[2:]

    for router in bad_routers:
        router.probably_malicious = True

    utils.introduce(good_routers)
    utils.introduce(bad_routers)
    utils.introduce(good_routers, random.sample(bad_routers, 2))

    for router in good_routers:
        for peer in router.peers[:options.pre_trusted]:
            if peer.router in good_routers:
                router.tbucket[peer.long_id] = peer
    
        for peer in router:
            for _ in range(random.randint(0,10)):
                router.transact_with(peer)

    for router in good_routers:
        router.tbucket.calculate_trust()

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

    utils.log("Emulating %s iterations of transactions with all peers." % "{:,}".format(options.transactions))
    for _ in range(options.transactions):
        for p in good_peer.peers:
            good_peer.transact_with(p)
    
        for router in routers:
            for peer in router.peers:
                router.transact_with(peer)

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
            print any(self.collective)
            raise SystemExit
            response = []
            for peer in self.peers:
                data = peer.jsonify()
                if any(filter(lambda r: r.node == peer, self.collective)):
                    data['trust'] += 1
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
    for router in good_peers:
        for peer in random.sample(router.peers, 2):
            router.tbucket[peer.long_id] = peer

    divisor = 4
    if options.nodes < 10: divisor = 2
    utils.introduce(good_peers, random.sample(routers, options.nodes / divisor))

    utils.log("Emulating %s iterations of transactions with all peers." % "{:,}".format(options.transactions))
    for _ in range(options.transactions):
        for router in good_peers:
            for peer in router.peers:
                router.transact_with(peer)
    
#       for router in routers:
#           for peer in router.peers:
#               router.transact_with(peer)

    good_peers[0].tbucket.calculate_trust()

    good_peers.extend(routers)
    return {"routers": all_routers}

def threat_model_c(options):
    """
    Malicious Collectives with camouflage.
    Malicious peers try to earn high local trust from good peers by providing
    authentic serices in f% of all cases.
    """
    pass

def threat_model_d(options):
    """
    Malicious peers who are strategically organised into two groups.
    One group of peers act as normal peers and try to increase their global
    reputation by only providing good services and use the reputation they
    gain to boost the trust values of another group of malicious peers.
    """
    pass

def threat_model_e(options):
    """
    Sybil attack. A thousand malicious peers who only provide bad services,
    who're then replaced with a new similarly malicious identity once contacted
    by good peers.
    """
    pass

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

    bad_peers = utils.generate_routers(options, minimum=10, router_class=EvilRouter)
    utils.log(bad_peers)
    good_peer = utils.Router()
    good_peer.routers = bad_peers
    [r.routers.append(good_peer) for r in bad_peers]

    utils.introduce(good_peer, random.sample(bad_peers, options.nodes))

    utils.log("Emulating %s transactions with each peer." % "{:,}".format(options.transactions))
    for _ in range(options.transactions):
        for p in good_peer.peers:
            good_peer.transact_with(p)
    good_peer.tbucket.calculate_trust()

    bad_peers.insert(0, good_peer)
    return {"routers": bad_peers}

map = {
        "one": scenario_one,
        "A": threat_model_a,
        "B": threat_model_b,
        "F": threat_model_f
      }


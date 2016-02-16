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
    Half of the population are good peers.
    Pre-trusted peers are selected from within the set of good peers though
    this can be made to overextend by setting |P| > (|nodes| / 2).

    Makes for an uncomplicated calculate_trust() computation.
    """
    routers      = utils.generate_routers(options, minimum=4)
    good_routers = routers[:len(routers) / 2]
    bad_routers  = routers[len(routers) / 2:]


    [setattr(_, "probably_malicious", True) for _ in bad_routers]

    utils.introduce(good_routers)
    
    [_.tbucket.append(_.peers[:options.pre_trusted]) for _ in good_routers]
    
    utils.introduce(bad_routers)
    
    utils.introduce(good_routers, bad_routers)

    # Note that this is based on a definite transaction count but that it's
    # through a random transaction count that the distributed trust algorithm
    # can be used to detect malicious peers via the set of pre-trusted peers.
    utils.log("Emulating %s iterations of transactions with all peers." % \
        "{:,}".format(options.transactions))
    for _ in range(options.transactions):
        for router in routers:
            for peer in router:
                c = random.randint(0, 1)
                if options.verbose:
                    utils.log("%s is making %i transactions with %s." % (router, c, peer))
                [router.transact_with(peer) for i in range(c)]

        # Calculate trust every 5 rounds here. The periodicity in reality is a
        # function of network size.
        if _ > 1 and not (_+1) % 5:
            for i, router in enumerate(routers):
                utils.log("%i %s %s is sensing." % (i+1, router, router.node))
                router.tbucket.calculate_trust()

    # The return value of a scenario is used to populate "locals" in the event
    # that you choose to use the --repl flag to spawn an interactive interpreter.
    return {"routers": routers}

def scenario_two(options):
    """
    Half of the population are good peers.
    Pre-trusted peers are selected from within the set of good peers though
    this can be made to overextend by setting |P| > (|nodes| / 2).

    A mix of new peers are introduced every 1/5th of the iteration count.
    Good peers have a 1 in 250 chance of receiving negative feedback from other
    good peers.

    This scenario has the highest likelihood of exhibiting consensus events.
    """
    routers      = utils.generate_routers(options, minimum=4)
    good_routers = routers[:len(routers) / 2]
    bad_routers  = routers[len(routers) / 2:]


    [setattr(_, "probably_malicious", True) for _ in bad_routers]

    utils.introduce(good_routers)
    
    [_.tbucket.append(_.peers[:options.pre_trusted]) for _ in good_routers]
    
    utils.introduce(bad_routers)
    
    utils.introduce(good_routers, bad_routers)

    # Note that this is based on a definite transaction count but it's through a
    # random transaction count with the possibility of some peers not transacting
    # with some of their peers at all that the distributed trust algorithm can be
    # used to detect malicious peers via the set of pre-trusted peers alone.
    utils.log("Emulating %s iterations of transactions with all peers." % \
        "{:,}".format(options.transactions))
    for _ in range(options.transactions):
        for router in routers:
            for peer in router:
                if not random.randint(0, 1): continue
                if not router.probably_malicious and not peer.router.probably_malicious:
                    if peer.trust and random.randint(0, 250) == 1:
                        utils.log("Good peer %s is having a bad transaction with good peer %s." % \
                            (router.node, peer))
                        router.transact_with(peer, transaction_type=False)
                        continue
                router.transact_with(peer)

        # Calculate trust every 5 rounds here. Normally the periodicity would be
        # a function of network size.
        if _ > 1 and not (_+1) % 5:
            for i, router in enumerate(routers):
                utils.log("%i %s %s is sensing." % (i+1, router, router.node))
                router.tbucket.calculate_trust()

        # Introduce a mix of new peers every 1/5th of the iteration count
        if _ > 5 and not _ % (options.transactions / 5):
            new_good_routers = utils.generate_routers(options, maximum=random.randint(1, 3))
            new_bad_routers  = utils.generate_routers(options,
                                                   maximum=random.randint(1, 3),
                                                   attrs={'probably_malicious': True})
            
            routers.extend(new_good_routers)
            routers.extend(new_bad_routers)
            [setattr(r, "routers", routers) for r in routers]

            utils.introduce(new_good_routers, random.sample(routers,
                random.choice(range(2, len(routers)))))
            utils.introduce(new_bad_routers,  random.sample(routers,
                random.choice(range(2, len(routers)))))
            
            for r in new_good_routers:
                utils.log("Introduced %s %s into the system." % (r, r.node))
            for r in new_bad_routers:
                utils.log("Introduced %s %s into the system." % (r, r.node))

    return {"routers": routers}

def scenario_three(options):
    """
    Most of the population are good peers.
    Pre trusted-peers are maximally deflationary.

    A mix of new peers are introduced every 1/5th of the iteration count.
    Good peers have a 1 in 250 chance of receiving negative feedback from other
    good peers.
    """
    class EvilRouter(utils.Router):

        def __init__(self):
            utils.Router.__init__(self)
            self.probably_malicious = False

        def render_peers(self):
                response = []
                for peer in self.peers:
                    data = peer.jsonify()
                    low  = 0.5 - (data['transactions'] * self.node.epsilon)
                    data['trust'] = random.choice([low, 0])
                    response.append(data)
                return response

    routers      = []
    good_routers = utils.generate_routers(options, minimum=4)
    bad_routers  = utils.generate_routers(options, minimum=1,
                                                   maximum=options.pre_trusted,
                                                   router_class=EvilRouter)
    routers.extend(good_routers)
    routers.extend(bad_routers)

    [setattr(r, "routers", routers) for r in routers]
    utils.introduce(routers)
    
    [r.tbucket.append(_) for _ in r.peers if _.router.__class__.__name__ == \
    "EvilRouter" for r in good_routers]
    

    # Note that this is based on a definite transaction count but it's through a
    # random transaction count with the possibility of some peers not transacting
    # with some of their peers at all that the distributed trust algorithm can be
    # used to detect malicious peers via the set of pre-trusted peers alone.
    utils.log("Emulating %s iterations of transactions with all peers." % \
        "{:,}".format(options.transactions))
    for _ in range(options.transactions):
        for router in routers:
            for peer in router:
                if not random.randint(0, 1): continue
                if not router.probably_malicious and not peer.router.probably_malicious:
                    if random.randint(0, 250) == 1:
                        utils.log("Good peer %s is having a bad transaction with good peer %s." % \
                            (router.node, peer))
                        router.transact_with(peer, transaction_type=False)
                        continue
                router.transact_with(peer)

        # Calculate trust every 5 rounds here. Normally the periodicity would be
        # a function of network size.
        if _ > 1 and not (_+1) % 5:
            for i, router in enumerate(routers):
                utils.log("%i %s %s is sensing." % (i+1, router, router.node))
                router.tbucket.calculate_trust()

        # Introduce a mix of new peers every 1/5th of the iteration count
        if _ > 5 and not _ % (options.transactions / 5):
            new_good_routers = utils.generate_routers(options,
                                                   maximum=random.randint(1, 3))
            new_bad_routers  = utils.generate_routers(options,
                                                   maximum=random.randint(1, 3),
                                                   attrs={'probably_malicious': True})
            
            routers.extend(new_good_routers)
            routers.extend(new_bad_routers)
            
            [setattr(r, "routers", routers) for r in routers]

            utils.introduce(new_good_routers, random.sample(good_routers,
                random.choice(range(2, 6))))
            utils.introduce(new_bad_routers,  random.sample(good_routers,
                random.choice(range(2, 6))))
            
            for r in new_good_routers:
                utils.log("Introduced %s %s into the system." % (r, r.node))
            for r in new_bad_routers:
                utils.log("Introduced %s %s into the system." % (r, r.node))

    return {"routers": routers}

def scenario_four(options):
    """
    There are no malicious peers.
    A mix of new peers are introduced every 1/5th of the iteration count.
    Peers have a 1 in 250 chance of receiving negative feedback from eachother.

    This is to mimic a real-life system with growth from a small number of
    initial users.
    """
    routers = utils.generate_routers(options, minimum=4)

    utils.introduce(routers)
    
    [_.tbucket.append(_.peers[:options.pre_trusted]) for _ in routers]

    # Note that this is based on a definite transaction count but it's through a
    # random transaction count with the possibility of some peers not transacting
    # with some of their peers at all that the distributed trust algorithm can be
    # used to detect malicious peers via the set of pre-trusted peers alone.
    utils.log("Emulating %s iterations of transactions with all peers." % \
        "{:,}".format(options.transactions))
    for _ in range(options.transactions):
        for router in routers:
            for peer in router:
                if not random.randint(0, 1): continue
                if not router.probably_malicious and not peer.router.probably_malicious:
                    if peer.trust and random.randint(0, 250) == 1:
                        utils.log("Peer %s is having a bad transaction with %s." % \
                            (router.node, peer))
                        router.transact_with(peer, transaction_type=False)
                        continue
                router.transact_with(peer)

        # Calculate trust every 5 rounds here. Normally the periodicity would be
        # a function of network size.
        if _ > 1 and not (_+1) % 5:
            for i, router in enumerate(routers):
                utils.log("%i %s %s is sensing." % (i+1, router, router.node))
                router.tbucket.calculate_trust()

        # Introduce a mix of new peers every 1/5th of the iteration count
        if _ > 5 and not _ % (options.transactions / 5):
            new_routers = utils.generate_routers(options, maximum=random.randint(1, 3))
            
            routers.extend(new_routers)
            [setattr(r, "routers", routers) for r in routers]

            utils.introduce(new_routers, random.sample(routers,
                random.choice(range(2, len(routers)))))
            
            for r in new_routers:
                utils.log("Introduced %s %s into the system." % (r, r.node))

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
    
    utils.introduce(good_peer, routers)

    routers.insert(0, good_peer)
    
    utils.log("Emulating %s iterations of transactions with all peers." % \
        "{:,}".format(options.transactions))
    for _ in range(options.transactions):
        for router in routers:
            for peer in router.peers:
                if not random.randint(0, 1): continue
                router.transact_with(peer)

        # Calculate trust every 5 rounds here. Normally the periodicity would be
        # a function of network size.
        if _ > 1 and not (_+1) % 5:
            for i, router in enumerate(routers):
                utils.log("%i %s %s is sensing." % (i+1, router, router.node))
                router.tbucket.calculate_trust()

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
                    data['trust'] = peer.transactions * self.node.epsilon
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
    [_.tbucket.append(_.peers[:options.pre_trusted]) for _ in good_peers]

    divisor = 1 if options.nodes == 1 else 2
    utils.introduce(good_peers, random.sample(routers, len(routers) / divisor))

    utils.log("Emulating %s iterations of transactions with all peers." % \
        "{:,}".format(options.transactions))
    for _ in range(options.transactions):
        for router in all_routers:
            for peer in router.peers:
                if not random.randint(0, 1): continue
                router.transact_with(peer)

        # Calculate trust every 5 rounds here. Normally the periodicity would be
        # a function of network size.
        if _ > 1 and not (_+1) % 5:
            for i, router in enumerate(routers):
                utils.log("%i %s %s is sensing." % (i+1, router, router.node))
                router.tbucket.calculate_trust()

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
        for router in routers:
            for peer in router.peers:
                if not random.randint(0, 1): continue
                router.transact_with(peer)

        # Calculate trust every 5 rounds here. Normally the periodicity would be
        # a function of network size.
        if _ > 1 and not (_+1) % 5:
            for i, router in enumerate(routers):
                utils.log("%i %s %s is sensing." % (i+1, router, router.node))
                router.tbucket.calculate_trust()

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
                    data['trust'] = 0.5 + (peer.transactions * \
                        self.node.epsilon)
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
                    data['trust'] = max(0.5 + (peer.transactions * \
                        self.node.epsilon), 0.5)
                response.append(data)
            return response
    
    bad_peers        = utils.generate_routers(options, minimum=10,
                                              router_class=EvilRouter)
    accomplice_peers = utils.generate_routers(options, minimum=10,
                                              router_class=AccompliceRouter)
    good_peers       = utils.generate_routers(options, minimum=20)

    routers = []
    routers.extend(bad_peers)
    routers.extend(accomplice_peers)
    routers.extend(good_peers)

    [setattr(r, "collective", bad_peers) for r in bad_peers]
    [setattr(r, "collective", bad_peers) for r in accomplice_peers]

    [setattr(r, "routers", routers) for r in routers]

    utils.introduce(routers)
    
    # Set good peers up with some pre-trusted friends
    [_.tbucket.append(random.sample(_.peers, options.pre_trusted)) for _ in good_peers]

    utils.log("Emulating %s iterations of transactions with all peers." % \
        "{:,}".format(options.transactions))
    for _ in range(options.transactions):
        for router in good_peers:
            for peer in router.peers:
                if not random.randint(0, 1): continue
                router.transact_with(peer)

        # Accomplice routers work by doubling the trust trust rating of
        # peers in the collective, which necessitates some good transactions
        for router in routers:
            for peer in router.peers:
                if not random.randint(0, 1): continue
                router.transact_with(peer)

        # Calculate trust every 5 rounds here. Normally the periodicity would be
        # a function of network size.
        if _ > 1 and not (_+1) % 5:
            for i, router in enumerate(routers):
                utils.log("%i %s %s is sensing." % (i+1, router, router.node))
                router.tbucket.calculate_trust()

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
                if not random.randint(0, 1): continue 
                positive_transaction = router.transact_with(peer)
                
                if positive_transaction == False:
                    router.dereference(peer, and_router=True)
                    new_router = utils.Router()
                    new_router.probably_malicious = True
                    utils.introduce(router, new_router)

        # Accomplice routers work by doubling the trust trust rating of
        # peers in the collective, which necessitates some good transactions
        for router in routers:
            for peer in router.peers:
                if not random.randint(0, 1): continue
                router.transact_with(peer)
        
        # Calculate trust every 5 rounds here. Normally the periodicity would be
        # a function of network size.
        if _ > 1 and not (_+1) % 5:
            for i, router in enumerate(routers):
                utils.log("%i %s %s is sensing." % (i+1, router, router.node))
                router.tbucket.calculate_trust()

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

    bad_peers  = utils.generate_routers(options, minimum=10,
                                        router_class=EvilRouter)
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
        # Accomplice routers work by doubling the trust trust rating of
        # peers in the collective, which requires some good transactions
        for router in routers:
            for peer in router.peers:
                if not random.randint(0, 1): continue
                router.transact_with(peer)

        # Calculate trust every 5 rounds here. Normally the periodicity would be
        # a function of network size.
        if _ > 1 and not (_+1) % 5:
            for i, router in enumerate(routers):
                utils.log("%i %s %s is sensing." % (i+1, router, router.node))
                router.tbucket.calculate_trust()

    return {"routers": routers}

map = {
        "one":   scenario_one,
        "two":   scenario_two,
        "three": scenario_three,
        "four":  scenario_four,
        "A": threat_model_a,
        "B": threat_model_b,
        "C": threat_model_c,
        "D": threat_model_d,
        "E": threat_model_e,
        "F": threat_model_f
      }


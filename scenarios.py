# _*_ coding: utf-8 _*_
import utils
import random

def scenario_one(options):
    # TODO: Pre-trusted and malicious peers with at least 10 neighbours
    #       Good peers with at least 2 neighbours.
    routers = utils.generate_routers(options)
    router = routers[0]
    for peer in router.peers[:options.pre_trusted]:
        router.tbucket[peer.long_id] = peer
    
    for peer in router:
        for _ in range(random.randint(0,10)):
            router.transact_with(peer)

    router.tbucket.calculate_trust()
    return {"routers": routers}
    for router in routers:
        print router
        router.tbucket.calculate_trust()

def thread_model_a(options):
    """
    Independently malicious peers who're not initially aware of eachother
    """
    pass

def thread_model_b(options):
    """
    Chain of Malicious Collectives who know eachother upfront and
    deterministically give a high trust value to another malicious peer.
    Resembles a malicious chain of mutual high local trust values.
    """
    pass

def thread_model_c(options):
    """
    Malicious Collectives with camouflage.
    Malicious peers try to earn high local trust from good peers by providing
    authentic serices in f% of all cases.
    """
    pass

def thread_model_d(options):
    """
    Malicious peers who are strategically organised into two groups.
    One group of peers act as normal peers and try to increase their global
    reputation by only providing good services and use the reputation they
    gain to boost the trust values of another group of malicious peers.
    """
    pass

def thread_model_e(options):
    """
    Sybil attack. A thousand malicious peers who only provide bad services,
    who're then replaced with a new similarly malicious identity once contacted
    by good peers.
    """
    pass

def thread_model_f(options):
    """
    Virus disseminating peers who send one inauthentic virus infected file every
    100th request.
    """
    pass

map = {
        "one": scenario_one,
      }


# _*_ coding: utf-8 _*_
import utils
import random

def scenario_one(node_count):
    routers = utils.generate_routers(node_count)
    router = routers[0]
    for peer in router.peers[:4]:
        router.tbucket[peer.long_id] = peer
    
    for peer in router:
        for _ in range(random.randint(0,10)):
            peer.transact()

    router.tbucket.calculate_trust()
    return {"routers": routers}
    for router in routers:
        print router
        router.tbucket.calculate_trust()


map = {
        "one": scenario_one,
      }


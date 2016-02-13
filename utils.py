# _*_ coding: utf-8 _*_
import math
import time
import uuid
import pprint
import random
import hashlib
import binascii
import datetime

try:
    import numpy
except ImportError:
    numpy = None

class Node(object):
    """
    Nodes are our local representation of remote routing tables.
    A Node represents what a Router sees of another Router in the network.
    """
    def __init__(self, node_id=None, ip="127.0.0.1", port=None, router=None):
        
        if isinstance(node_id, long):
            try:    node_id = binascii.unhexlify('%x' % node_id)
            except: return Node(node_id, ip, port, router)
        self.id           = "Test Node" # Uncomment the following if you need
                                        # realistic node IDs.
#        self.id           = node_id or hashlib.sha1(
#                                hex(id(self)) +
#                                datetime.datetime.now().strftime("%f")
#                            ).digest()
        self.ip           = ip
        self.port         = port or random.randint(0, 99999)
        self.trust        = 0.50
        self.router       = router
        self.epsilon      = 0.0001
#        self.long_id      = long(self.id.encode("hex"), 16)
        self.long_id      = self.port
        self.transactions = 0

    @property
    def threeple(self):
        return [self.long_id, self.ip, self.port]

    def copy(self, router=None):
        # NOTE: Don't deepcopy(self) unless you want the attached graph..
        node         = Node(*self.threeple)
        node.epsilon = self.epsilon
        node.router  = router or self.router
        return node

    def transact(self, positively=True, router=None):
        if positively:
            self.trust += self.epsilon
        else:
            if router and router.no_prisoners:
                self.trust = 0
            else:
                # In a real system we will have incremented trust for the transaction
                # in good faith and would decrement by 2 * epsilon to account for this.
                self.trust -= self.epsilon 
        
        self.transactions += 1

    def jsonify(self):
        response = {}
        response['node']         = [self.long_id, self.ip, self.port]
        response['trust']        = self.trust
        response['transactions'] = self.transactions
        return response

    def __eq__(self, other):
        if not hasattr(other, "id") or not hasattr(other, "port"):
            return False
        return self.id == other.id and self.port == other.port

    def __repr__(self):
        malicious = None
        if self.router:
            malicious = self.router.probably_malicious
        return "<%s Node %s:%5i %.4fT/%i>" %\
            ("+" if not malicious else "-",
            self.ip,
            self.port,
            self.trust,
            self.transactions)

class Router(object):
    """
    A Router is responsible for maintaining awareness of other routing tables
    and what their attributes are as network nodes.
    """
    def __init__(self):
        self.id                 = hashlib.sha1(hex(id(self))).hexdigest()
        self.node               = Node(router=self)
        self.network            = "Test Network"
        self.no_prisoners       = None
        self.peers              = []
        self.routers            = []
        self.tbucket            = PTPBucket(self)
        self.probably_malicious = False

    @property
    def malicious(self):
        """
        Override this property to programatically define the behavior of
        malicious peers.
       
        You could, for instance, make a peer routing table that's malicious
        only on Thursdays.
        """
        return self.probably_malicious

    def get(self, nodeple):
        nodeple = list(nodeple)
        for p in self.peers:
            if p.threeple == nodeple:
                return p

    def render_peers(self):
        """
        This method is for overriding in test scenarios to emulate
        routers who give positive trust ratings to malicious peers.
        """
        return [peer.jsonify() for peer in self.peers]

    def transact_with(self, peer, transaction_type=None):
        """
        Update local trust rating and transaction count of peer
        """
        if hex(id(peer)) == hex(id(self.node)):
            return
    
        if not max(peer.trust, 0):
            return None

        # Locate the routing table responsible for the peer we're dealing with
        router = filter(lambda x: x.node == peer, self.routers)
        if not any(router): return
        router = router[0]
        
        # Routers can be subclassed to turn their .malicious attr into a property
        # with statistical variance. E.g. to return True every 100th transaction.
        if transaction_type == None:
            transaction_type = not router.malicious
 
        peer.transact(positively=transaction_type, router=self)
        
        #log("[%s] %s <-- %s" % \
        #    ("+" if not maliciousness else "-", self.node, peer))

        # Reinforce the network by making ourselves aware of this peers' peers
        for node in router.peers:
            if node == self.node or node in self.peers:
                continue
            self.peers.append(node.copy(router=self))

        # and make the peer routing table aware of our peers.
        for node in self.peers:
            if node == router.node or node in router.peers:
                continue
            router.peers.append(node.copy(router=router))

        # NoneType indicates an unreachable peer, True indicates a positive
        # transaction and False means the remote peer can be said to have
        # provided a malicious resource.
        return transaction_type

    def dereference(self, peer, and_router=False):
        """
        Force a router to forget a peer and optionally the router it represents.
        """
        if peer == self.node:
            return

        self.peers.remove(peer)
        if and_router != True:
            return

        router = filter(lambda x: x.node == peer, self.routers)
        if not any(router): return
        self.routers.remove(router[0])

    def __eq__(self, other):
        if not hasattr(other, "id"):
            return False
        return self.id == other.id

    def __len__(self):
        return len(self.peers)

    def __iter__(self):
        return iter(self.peers)

    def __repr__(self):
        return "<%s %s %s with %i peers>" % \
            ("-" if self.probably_malicious else "+",
             self.__class__.__name__, self.id, len(self.peers))

class TBucket(dict):
    """
    A set of pre-trusted peers. The aim is to totally starve
    errant peers of trust such that they're not selected for
    service. It's done by asking all intermediate peers what their
    rating of a given peer is.

    High trust ratings aren't particularly meaningful, so long as it's not 0.

    Psuedocode translation from EigenTrust++:

        S(i,j) = max(j.trust / j.transactions, 0)
        C(i,j) = max(max(S(i,j) / max(sum(i,m), 0)), len(P))
        Where P is the set of pre-trusted peers.

        SIMILARITY of feedbacks from peers u and v is defined as:
        sim(u,v) = 1 - sqrt(sum(pow((tr(u,w) - tr(v,w)),2)) / len(R0(u,v)))
              tr = v.trust, u.trust / R0(u, v) 
        Where R(u,v) is the amount of transactions between u and v.
        
        CREDIBILITY of feedbacks is defined as:
        f(i,j)  = sim(i,j) / sum([sim(i,m) for i in R1(i)]
        where R(i) is the set of peers who've had transactions with peer i.

        fC(i,j) = f(i,j) * C(i,j)

         l(i,j) = max(fC(i,j), 0) / sum([max(fC(i,m), 0) for i in P])
  
         t(i,j) = sum(l(i,k) + C(k,j))
  
         w(i,j) = (i - b) * C(j,i) + b * sim(j,i)
              b = 0.85

    """
    def __init__(self, router, *args, **kwargs):
        self.beta       = 0.85  # proportion factor 
        self.gamma      = 0.0
        self.iterations = 100
        self.router     = router
        self.messages   = []
        dict.__init__(self, *args, **kwargs)
    
    def append(self, nodes):
        if not isinstance(nodes, list):
            nodes = [nodes]

        c = len(self) + len(nodes)
        for node in nodes:
            if not isinstance(node, Node):
                continue
            node.trust += 1.0 / c
            self[node.long_id] = node

    def get(self, node, endpoint=""):
        """
        Ask a remote peer about their peers.
        """
        if not node:
            return
        for router in self.router.routers:
            if router.node == node:
                return router.render_peers()

    def S(self, i, j):
        if not j.transactions:
            return 0
        r = max(j.trust / j.transactions, 0)
        log("S:   %s %s %i" % (i, j, r))
        return r

    def C(self, i, j):
        score = 0
        for _, m in enumerate(self):
            if _ >= self.iterations: break
            if m in self:
                score +=  1.0 / len(self)
            score += self.S(i, m)
        if not score:
            return 0
        s = self.S(i,j) / score
        log("C:   %s %s %i" % (i, j, s))
        return s

    def sim(self, u, v):
        score = 0
        common_peers = self.common_peers(u, v)
        s = sum([pow((self.tr(u, w) - self.tr(v, w)), 2) for w in common_peers])
        if not common_peers:
            return 0
        s = s / len(common_peers)
        sim = 1 - math.sqrt(s)
        log("sim: %s %s %i" % (u, v, sim))
        return sim

    def tr(self, u, w):
        if not isinstance(u, Node):
            u = self.router.get(u)
        if not isinstance(w, Node):
            w = self.router.get(w)
        s = self.R0(u,w)
        if not s:
            tr = 0
        else:
            tr = u.trust + w.trust / s
        log("tr:  %s %s %i" % (u, w, tr))
        return tr

    def R0(self, u, v):
        results = []
        
        ur = self.get(u, self.router.network)
        vr = self.get(v, self.router.network)

        if ur and not vr:
            ur = [i for i in ur if Node(*i['node']) == v]
            if any(ur):
                return ur[0]['transactions']

        if vr and not ur:
            vr = [i for i in vr if Node(*i['node']) == u]
            if any(vr):
                return vr[0]['transactions']

        if ur and vr:
            R0 = (ur[0]['transactions'] + vr[0]['transactions']) / 2
        else:
            R0 = 0
    
        log("R0:  %s %s %i" % (u, v, R0))
        return R0

    def R1(self, i):
        """
        The set of our peers who've had transactions with peer i.
        """
        results = []
        for peer in self.router:
            remotes_peers = self.get(peer)
            for friend_of_a_friend in remotes_peers:
                if friend_of_a_friend['node'] == i.threeple and friend_of_a_friend['transactions']:
                    results.append(peer)
        log("R1:  %s %s" % (i, str(results)))
        return results

    def f(self, i, j):
        # Feedback credibility
        s = sum([self.sim(_, j) for _ in self.R1(i)])
        
        if not s:
            f = 0
        else:
            f = self.sim(i, j) / s
        log("f:   %s %s %i" % (i, j, f))
        return f

    def fC(self, i, j):
        fC = self.f(i,j) * self.C(i, j)
        log("fC:  %s %s %i" % (i, j, fC))
        return fC

    def l(self, i, j):
        s = sum([max(self.fC(i,m), 0) for m in self])
        if not s:
            l = 0
        else:
            l = max(self.fC(i,j), 0) / s
        log("l:   %s %s %i" % (i, j, l))
        return l

    def t(self, i, j):
        score = 0
        for _, k in enumerate(self.router):
            if _ >= self.iterations: break
            score += self.l(i,k) + self.C(k,j)
        log("t:   %s %s %i" % (i, j, score))
        return score

    def w(self, i, j):
        w = (1.0 - self.beta) * self.C(j,k) + (self.beta * self.sim(j, i))
        log("w:   %i" % w)
        return w

    def common_peers(self, i, j):
        """
        Returns the set of the common peers between sets i and j who have
        transactions > 1, by node triple.
        """
        ir = self.get(i, self.router.network)
        jr = self.get(j, self.router.network)
        
        if not ir or not jr:
            return []

        ir = [tuple(p['node']) for p in ir if p['transactions']]
        jr = [tuple(p['node']) for p in jr if p['transactions']]

        result = list(set(ir).intersection(jr))
        log("cmn: %s %s %i: %s" % (i, j, len(result), result))
        return result

    def aggregate_trust(self):
        """
        Performs t(self, remote_peer) for all peers in our routing table.
        Performs matrix activation given the result.
        """
        AC    = []
        peers = [peer for peer in self.router]
        x     = len(peers)
        if x / 5:
            x = x / 5
        elif x / 2:
            x = x / 2
        for i in range(x):
            AC.append(peers[i:i+x])
        return AC

    def calculate_trust(self):
        """
        Weight peers by the ratings assigned to them via trusted peers.
        """
        for remote_peer in self.router.peers:
            new_trust = self.t(self.router.node, remote_peer)
            self.messages.append("Recalculated trust of %s as %.4f." %\
                (remote_peer, new_trust))
            remote_peer.trust = new_trust
        # AC = self.aggregate_trust()
        self.read_messages()
        # log(AC)

    def read_messages(self):
        for message in self.messages:
            log(message)
        self.messages = []

    def __iter__(self):
        return iter(self.values())

    def __repr__(self):
        return "<TBucket of %i pre-trusted peers>" % len(self)

class PTPBucket(dict):
    """
    A two-tiered bucket of pre-trusted peers.

    The extended set cannot contain members of the real set and the real set
    mustn't contain members of the extended set. The members of the set of
    pre-trusted peers, referred to as P, are queried about every peer we know
    of except for themselves providing the cardinality of P is greater than a
    pre set percentage of the size of the network, with a frequency that's also
    tied to the size of the network as we see it. The larger the network the
    less often you should perform calculate_trust().
    
    The responses about peers are first checked for trust rating inflation,
    deflation and whether they're just impossible in relation to their reported
    transaction count.

    For each peer we then calculate the median altruism rating of all obtained
    responses, which is the number of transactions divided by the trust rating
    once normalised to its defaults (IE. trust - 0.5 / transactions * epsilon).

    For peers who have a median altruism rating below 1.00 minus our cutoff
    point, say 5%, we say that a consensus has been acheived via set P that
    the peer in question is malicious. This enables use to identify nodes
    we should distrust without having to transact with them at all.

    Members of the extended set, referred to as EP, are being monitored for
    retaining an altruism score of 1.00 (100% ratio of trust to transactions)
    and can be graduated into set P once they have rendered reliable service
    to at least either half of our set of pre-trusted peers or if none are
    available, directly to ourselves.
    """
    def __init__(self, router, *args, **kwargs):
        # Peers trusted by pre-trusted peers. These are peers we're observing
        # for possible inclusion into the set of pre-trusted peers.
        self.extent  = {}
        
        # We require alpha satisfactory transactions and altruism(peer) = 1
        # before we graduate a remote peer from the extended set into this set.
        self.alpha   = 500
        
        # The minimum satisfactory transactions required with at least half of
        # the members of this set, or if there are no members of this set, with
        # ourselves before graduating remote peers into the extended set.
        self.beta    = 250
        
        # Percentage of purportedly malicious downloads before a far peer can be
        # pre-emptively dismissed for service. 0.5% by default. This means that
        # we'll tolerate one unsatisfactory download out of every 200 per
        # threat model F.
        self.delta   = 0.005
        
        # Percentage of network peers we need to trust before we start
        # letting them cut us off from peers they report to be malicious.
        self.gamma = 0.04
        
        # Access to the routing table.
        self.router  = router
        
        # Whether we're logging stats.
        self.verbose = None
        
        dict.__init__(self, *args, **kwargs)

    @property
    def all(self):
        copy = self.copy()
        copy.update(self.extent)
        return iter(copy.values())

    def append(self, nodes):
        if not isinstance(nodes, list):
            nodes = [nodes]

        for node in nodes:
            if not hasattr(node, "long_id"):
                continue
            self[node.long_id] = node

    def get(self, node, about_node):
        """
        Ask a remote peer about a peer.
        """
        if not node:
            return
        for router in self.router.routers:
            if router.node == node:
                for _ in router.render_peers():
                    if _['node'] == about_node.threeple:
                        return _

    def mean(self, ls):
        if not isinstance(ls, (list, tuple)):
            return
        if numpy:
            [ls.remove(_) for _ in ls if _ == None or _ is numpy.nan]
        else:
            [ls.remove(_) for _ in ls if _ == None]
        if not ls: return 0.00
        mean = sum(ls) / float(len(ls))
        if self.verbose:
            log("mean:   %s %f" % (ls, mean))
        return mean

    def med(self, ls):
        if not numpy:
            med = median(ls)
        else:
            med =  numpy.median(numpy.array(ls))
        if self.verbose:
            log("med:    %s %f" % (ls, med))
        return med

    def median(self, l):
        if numpy:
            [l.remove(_) for _ in l if _ > 1 or _ < 0 \
             or not isinstance(_, (int, float)) or _ is numpy.nan]
        else:
            [l.remove(_) for _ in l if _ > 1 or _ < 0 \
             or not isinstance(_, (int, float))]
        if not len(l): return 0.00
        a = self.mean(l)
        m = self.med(l)
        me = self.mean([a, m])
        if self.verbose:
            log("me:     [%f, %f] %f" % (a, m, me))
        median = min(max(me, 0), 1)
        if self.verbose:
            log("median: %s %f" % (l, median))
        return median

    def altruism(self, i):
        # print i, 
        if isinstance(i, Node):
            i = {"trust": i.trust, "transactions": i.transactions}
        divisor = (i['transactions'] * self.router.node.epsilon)
        # print i, divisor
        a = i['trust'] - self.router.node.trust
        if not divisor and not a: return 1.00
        if not divisor: return 0.00
        # print a
        return a / divisor

    def calculate_trust(self):
        # Any superficially simple behaviors here can be enhanced with
        # decision trees.
        all_responses = {} 

        for peer in self.router:
            responses             = []
            altruism              = []
            local_altruism        = 0.00

            # Multiplier is the amount of transactions more than ourselves we're
            # checking a trusted peer is reporting they've satisfactorily had
            # with an untrustworthy peer. For small networks we would find it
            # interesting if a peer we depend on for consensus claims to have
            # had more than twice as many satisfactory transactions than
            # ourselves with a peer who we've only have had (100% - delta)
            # satisfactory transactions with.
            multiplier = 2.1 if len(self.router) < 40 else 1.1
            
            # Screen members of set EP for inflation/deflation.
            for extent_peer in self.extent.values():
                if extent_peer == peer: continue
                response = self.get(extent_peer, peer)
                if response and response['transactions']:
                    
                    # Check for peers in EP reporting high transaction count and
                    # high trust with peers we don't trust, indicating inflated scores.
                    if not peer.trust and peer.transactions > 5 * multiplier \
                        and response['transactions'] >= peer.transactions * multiplier \
                        and float("%.1f" % self.altruism(response)) >= 1.0:
                        if self.verbose:
                            log((peer, extent_peer, response))
                        if extent_peer.long_id in self.extent:
                            extent_peer.trust = 0
                            [setattr(_, "trust", 0) for _ in self.router.peers if _ == extent_peer]
                            log("Removing %s from EP for inflating trust ratings." % extent_peer)
                            del self.extent[extent_peer.long_id]

                    # Check for members of set EP reporting 100% unsatisfactory
                    # transactions with the peer in question but not reporting the
                    # peer as having trust == 0 when reporting altruism < 0.8.
                    if self.altruism(response) <= 0.8 and response['trust'] > 0:
                        if self.verbose:
                            log((extent_peer, peer, response))
                        if extent_peer.long_id in self:
                            log("Removing %s from EP for deflating trust ratings." % \
                                extent_peer)
                            del self.extent[extent_peer.long_id]

                    # Check for peers in EP reporting trust ratings greater or lower
                    # than what they could be in relation to reported transaction counts.
                    if (response['trust'] > 0.5 + (response['transactions'] * self.router.node.epsilon)) \
                    or (response['trust'] < 0.5 - (response['transactions'] * self.router.node.epsilon)) \
                    and response['trust'] and extent_peer.long_id in self.extent:
                        extent_peer.trust = 0
                        [setattr(_, "trust", 0) for _ in self.router.peers if _ == extent_peer]
                        log("Removing %s from EP for impossible trust ratings." % extent_peer)
                        del self.extent[extent_peer.long_id]
 
            # Ask members of set P about everyone in our routing table.
            for trusted_peer in self.values():
                if trusted_peer == peer: continue
                response = self.get(trusted_peer, peer)
                if response and response['transactions']:
                    responses.append((trusted_peer, response))
                    
                    if not trusted_peer in all_responses:
                        all_responses[trusted_peer] = [(peer, response)]
                    else:
                        all_responses[trusted_peer].append((peer, response))

            # Check for peers in P reporting high transaction count and
            # altruism > 1 - delta with peers we don't trust, which indicates
            # trusted peers giving inflated trust ratings.
            for trusted_peer, response in responses:
                if not peer.trust and peer.transactions > 5 * multiplier \
                    and response['transactions'] >= peer.transactions * multiplier \
                    and float("%.1f" % self.altruism(response)) >= 1.0:
                    if self.verbose:
                        log((peer, trusted_peer, response))
                    if trusted_peer.long_id in self:
                        trusted_peer.trust = 0
                        [setattr(_, "trust", 0) for _ in self.router.peers if _ == trusted_peer]
                        log("Removing %s from P for inflating trust ratings." % \
                            trusted_peer)
                        del self[trusted_peer.long_id]

                # Check for members of set P reporting 100% unsatisfactory
                # transactions with the peer in question but not reporting the
                # peer as having trust == 0 when reporting altruism < 0.5.
                if response['trust'] > 0 and self.altruism(response) <= 0.5 \
                    and response['transactions'] >= 5 * multiplier:
                    if self.verbose:
                        log((trusted_peer, peer, response))
                        log(self.altruism(response))
                    if trusted_peer.long_id in self:
                        log("Removing %s from P for deflating trust ratings." % \
                            trusted_peer)
                        del self[trusted_peer.long_id]

                # Check for peers in P reporting trust ratings greater or lower
                # than what they could be in relation to reported transaction counts.
                if (response['trust'] > 0.5 + (response['transactions'] * self.router.node.epsilon)) \
                or (response['trust'] < 0.5 - (response['transactions'] * self.router.node.epsilon)) \
                and response['trust'] and trusted_peer.long_id in self:
                    trusted_peer.trust = 0
                    [setattr(_, "trust", 0) for _ in self.router.peers if _ == trusted_peer]
                    log("Removing %s from P for impossible trust ratings." % trusted_peer)
                    del self[trusted_peer.long_id]
            
            if not peer.trust: continue

            local_altruism = float("%.1f" % self.altruism(peer))
            
            if (local_altruism + self.delta) <= 1.0:
                log("Local experience shows %s is malicious." % peer)
                peer.trust = 0
                continue

            median_reported_altruism = 0.00
            # Let our pre-trusted peers have some say about this if they
            # A) Represent at least gamma percent of who we know in the network.
            # B) Report having more experience than us with the peer in question.
            if float(len(self)) / len(self.router) >= self.gamma:
                
                # Filter responses to those from peers who report having more
                # experience than us with the peer in question if we're ascribing
                # a 100% altruism rating to this peer.
                filtered_responses = filter(lambda r:
                                        r[1]['transactions'] >= peer.transactions and \
                                        (float(r[1]['transactions'] - peer.transactions) / r[1]['transactions']) \
                                        >= 0.01,
                                        responses
                                  )

                # If we have good faith in the peer regardless of having had no
                # transactions with them we'll require the votes to come from
                # pre-trusted peers who've rendered excellent service to
                # mitigate the effect of maximally deflationary pre-trusted peers.
                if local_altruism >= 0.99:
                    filtered_responses = filter(lambda r: r[0].transactions > self.alpha,
                                                filtered_responses)


                for response in filtered_responses:
                    altruism.append(self.altruism(response[1]))

                # continue if we've had good service from the peer in question
                # and only received one vote, or if we've had perfect service
                # from the peer so far. Listen to trusted peers if we have no
                # prior transactions with the peer in question as this is really
                # what the system's about: Pre-emptively identifying
                # untrustworthy peers without having to transact with them.
                if not len(altruism) or (local_altruism == 1.0 and len(altruism) == 1) or \
                        (peer.transactions and local_altruism == 1.0):
                    continue
                
                if numpy:
                    [altruism.remove(_) for _ in altruism if _ == None or _ is numpy.nan]
                else:
                    [altruism.remove(_) for _ in altruism if _ == None]
                
                if self.verbose:
                    log(filtered_responses)
                    log("%s local_altruism %f" % (peer, local_altruism))

                log("%s %s" % (peer, altruism))
                
                median_reported_altruism = self.median(altruism)
                log("Median reported altruism: %f" % median_reported_altruism)
                # Check if global altruism is below our accepted threshold (delta) and
                # if it's reportedly less than our experience minus the accepted threshold
                # gamma, which is made to be a function of routing table size. 
                if (median_reported_altruism + self.delta) < 1.0:
                    log("Consensus from our trusted peers is that %s is malicious." % peer)
                    peer.trust = 0
                    continue
            
            # Don't adjust a peers' trust rating to more closely reflect the consensus
            # as this gives an innacurate reflection of their trust / transaction ratio
            # from our perspective.

            # Check who we can invite into the extended set.
            if (len(self) and float("%.1f" % median_reported_altruism) != 1.0) \
            or peer in self.all:
                continue
            
            # If we haven't continued from this peer we'll see if they can be
            # graduated into the extended set of pre-trusted peers using the
            # responses obtained earlier.
            #
            # We do this based on the peer having median_reported_altruism == 1
            # and either at least half of our trusted peers having at least
            # the minimum required transaction count (beta) with this peer or
            # if we're in need of some pre-trusted peers, this instance having
            # the necessary transaction count.
            votes = sum([1 for r in responses if r[1]['transactions'] >= self.beta])
            if len(self) and not votes: continue
            
            if (not len(self) and peer.transactions >= self.beta) \
            or (len(self) and votes >= (len(self) / 2)):
                if len(self):
                    log("votes: %s %i" % (peer, votes))
                log("Graduating %s into EP." % peer)
                self.extent[peer.long_id] = peer

        for peer in self.extent.copy().values():
            if float("%.1f" % self.altruism(peer)) != 1.0:
                log("Removing %s from the extended set of pre-trusted peers." % peer)
                del self.extent[peer.long_id]
                continue
            # Check if they're trustworthy enough to be a pre-trusted peer
            if peer.transactions >= self.alpha:
                log("Graduating %s from EP to P." % peer)
                del self.extent[peer.long_id]
                self[peer.long_id] = peer

        for peer in self.copy().values():
            if float("%.1f" % self.altruism(peer)) != 1.0:
                log("Removing %s from the set of pre-trusted peers." % peer)
                del self[peer.long_id]
        
        # Check the percentage of high transaction/altruism peers being
        # reported as untrustworthy by this peer.
        for trusted_peer, responses in all_responses.items():
            if not trusted_peer.long_id in self: continue
            x = 0
            for peer, response in responses:
                if not trusted_peer.long_id in self: break
                if response['transactions'] < peer.transactions \
                or peer.transactions < 20: continue
                if self.altruism(peer) > 0.95 and self.altruism(response) <= 0:
                    x += 1
                for cmp_peer, cmp_responses in all_responses.items():
                    if not cmp_peer in self.values() or cmp_peer == trusted_peer:
                        continue
                    for _peer, cmp_response in cmp_responses:
                        if _peer == peer and self.altruism(cmp_response) > 0.95:
                            x += 1
            if self.verbose:
                log("%s x: %i" % (trusted_peer, x))
            if x > len(self.router) * 0.7:
                log("Removing %s from P for deflating trust ratings." % trusted_peer)
                del self[trusted_peer.long_id]

        log("P:  %s" % str(self.values()))
        log("EP: %s" % str(self.extent.values()))

        for _ in sort_nodes_by_trust(self.router.peers):
            log(_)

        del all_responses

def generate_routers(options, minimum=None, maximum=None, attrs={}, router_class=Router):
    routers = []
    
    node_count = max(options.nodes, minimum)
    if maximum:
        node_count = min(node_count, maximum)
    
    log("Creating %s routing tables." % "{:,}".format(node_count))
    for _ in range(node_count):
        router                 = router_class()
        router.no_prisoners    = options.no_prisoners
        router.tbucket.verbose = options.verbose
        routers.append(router)

    for router in routers:
        router.routers = [r for r in routers if r != router]
        for key, value in attrs.items():
            setattr(router, key, value)
    
    return routers

def fabricate_transactions(node, floor=5, ceiling=75):
    node.transactions = random.randint(floor, ceiling)
    node.trust        = random.randint(floor, node.transactions)
    return node

def introduce(routers, secondary=[]):
    """
    Introduce a set of routers to one another or all routers of one set to all
    routers of a second set.
    """
    if not isinstance(routers, list):
        routers = [routers]
    if not isinstance(secondary, list):
        secondary = [secondary]
    
    if not any(secondary):
        log("Introducing %s routing tables to one another." % "{:,}".format(len(routers)))
        for router in routers:
            router.peers.extend([r.node.copy() for r in routers if r != router])
            router.peers = list(set(router.peers))
    else:
        log("Introducing %s to %s." % \
            ("a set of {:,} routing tables".format(len(routers)) if len(routers) \
                > 1 else "1 routing table", "a set of {:,} routing tables"\
                .format(len(secondary)) if len(secondary) > 1 else "1 routing table"))
        for router in routers:
            router.peers.extend([r.node.copy() for r in secondary if r != router])
            router.peers = list(set(router.peers))

        for router in secondary:
            router.peers.extend([r.node.copy() for r in routers if r != router])
            router.peers = list(set(router.peers))

    return routers

def configure(repl):
    repl.prompt_style                   = "ipython"
    repl.vi_mode                        = True
    repl.confirm_exit                   = False
    repl.show_status_bar                = False
    repl.show_line_numbers              = True
    repl.show_sidebar_help              = False
    repl.highlight_matching_parenthesis = True
    repl.use_code_colorscheme("native")

def format(data):
    fmt=[]
    tmp={}
    r_append=0
    for item in data:
        for key,value in item.items():
            if not key in tmp.keys():
                if value: tmp[key] = len(str(value))
            elif len(str(value)) > tmp[key]:
                if value: tmp[key] = len(str(value))
    for key,value in tmp.items():
        if (key == 'Hash') or (key =='State'): r_append=(key,key,value)
        else: fmt.append((key, key, value))  
    if r_append: fmt.append(r_append)
    return(fmt)

class tabulate(object):
    "Print a list of dictionaries as a table"
    def __init__(self, fmt, sep=' ', ul=None):
        super(tabulate,self).__init__()
        self.fmt   = str(sep).join('{lb}{0}:{1}{rb}'.format(key, width, lb='{', rb='}') for heading,key,width in fmt)
        self.head  = {key:heading for heading,key,width in fmt}
        self.ul    = {key:str(ul)*width for heading,key,width in fmt} if ul else None
        self.width = {key:width for heading,key,width in fmt}
    def row(self, data):
        return(self.fmt.format(**{ k:str(data.get(k,''))[:w] for k,w in self.width.iteritems() }))
    def __call__(self, dataList):
        _r = self.row
        res = [_r(data) for data in dataList]
        res.insert(0, _r(self.head))
        if self.ul:
            res.insert(1, _r(self.ul))
        return('\n'.join(res))

def table(data, ts=False):
    log(tabulate(format(data))(data), with_timestamp=ts)

def invoke_ptpython(env={}):
    try:
        from ptpython.repl import embed
    except ImportError:
        log("-repl requires ptpython")
        log("Please use \"pip install ptpython\" and try again")
        raise SystemExit
    p = pprint.PrettyPrinter()
    p = p.pprint
    l = {"p": p}
    l.update(env)
    log("\n^D to exit.", with_timestamp=False)
    embed(locals=l, configure=configure)

def log(message, with_timestamp=True):
    if not isinstance(message, (str, unicode)):
        message = pprint.pformat(message)

    if not with_timestamp:
        print(message)
        return

    for _ in message.split("\n"):
        print(datetime.datetime.now().strftime("%H:%M:%S.%f") + " " + _)

def sort_nodes_by_trust(nodes):
    if nodes == []: 
        return []
    else:
        pivot   = nodes[0]
        lesser  = sort_nodes_by_trust([x for x in nodes[1:] if x.trust < pivot.trust])
        greater = sort_nodes_by_trust([x for x in nodes[1:] if x.trust >= pivot.trust])
        return greater + [pivot] + lesser

def median(ls):
    ls = sorted(ls)
    if len(ls) < 1:
            return None
    if len(ls) %2 == 1:
            return ls[((len(ls)+1)/2)-1]
    else:
            return float(sum(ls[(len(ls)/2)-1:(len(ls)/2)+1]))/2.0
class colour:
    purple = '\033[95m' 
    blue = '\033[94m'
    green = '\033[92m'
    orange = '\033[93m'
    red = '\033[91m'
    end = '\033[0m'
    def disable(self):
        self.purple = ''
        self.blue = ''
        self.green = ''
        self.orange = ''
        self.red = ''
        self.end = ''

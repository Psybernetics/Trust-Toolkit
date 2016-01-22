# _*_ coding: utf-8 _*_
import math
import time
import copy
import pprint
import random
import hashlib
import binascii
from ptpython.repl import embed

class Node(object):
    def __init__(self, id=None, ip="127.0.0.1", port=None):
        if isinstance(id, long):
            id = binascii.unhexlify('%x' % id)
        self.id           = id or hashlib.sha1(time.asctime()).digest()
        self.long_id      = long(self.id.encode("hex"), 16)
        self.ip           = ip
        self.port         = port or random.randint(0, 99999)
        self.trust        = 0
        self.transactions = 0

    @property
    def threeple(self):
        return [self.long_id, self.ip, self.port]

    @property
    def copy(self):
        return copy.deepcopy(self)

    def transact(self):
        self.trust += 1
        self.transactions += 1

    def jsonify(self):
        response = {}
        response['node']         = [self.long_id, self.ip, self.port]
        response['trust']        = self.trust
        response['transactions'] = self.transactions
        return response

    def __eq__(self, other):
        if hasattr(other, "id") and self.id == other.id:
            return True
        return False

    def __repr__(self):
        return "<Node %s:%i %.2fT/%i>" %\
            (self.ip, self.port, self.trust, self.transactions)

class Router(object):
    def __init__(self):
        self.id      = hashlib.sha1(time.asctime()).hexdigest()
        self.node    = Node()
        self.network = "EigenTrust++ Test Network"
        self.peers   = []
        self.routers = []
        self.tbucket = TBucket(self)

    def get(self, nodeple):
        nodeple = list(nodeple)
        for p in self.peers:
            if p.threeple == nodeple:
                return p

    def __iter__(self):
        return iter(self.peers)

    def __repr__(self):
        return "<Router %s with %i peers>" % (self.id, len(self.peers))

class TBucket(dict):
    """
    A set of pre-trusted peers.

        Nodes residing on internal subnets. (No.)
        Nodes supplied by app.default_nodes/options.bootstrap.
        Nodes who're the first to be added to a new network.
        Nodes who've previously earned high trust over time.

    Peers have a normal placement in KBuckets but peers who also have a
    reference from a TBucket are considered to be inherently trustworthy.
    They can be relied upon to be honest in rating the trustworthiness of their
    peers.

    They must be the canonical reference to the Node instance as returned by
    RoutingTable.get_existing_node.

    Psuedocode translation from the sigma notation in EigenTrust++:

        S(i,j) = max(j.trust / j.transactions, 0)
        C(i,j) = max(max(S(i,j) / max(sum(i,m), 0)), len(P))
        Where P is the set of pre-trusted peers.

        SIMILARITY of feedbacks from peers u and v is defined as:
        sim(u,v) = 1 - sqrt(sum(pow((tr(u,w) - tr(v,w)),2)) / len(common_peers(u,v)))
              tr = v.trust, u.trust / R0(u, v) 
        Where R(u,v) is the cardinality of the set of transactions between u and v.
        
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
        self.alpha      = 0.0
        self.beta       = 0.85
        self.iterations = 100
        self.router     = router
        self.messages   = []
        dict.__init__(self, *args, **kwargs)
    
    def get(self, node, endpoint):
        for r in self.router.routers:
            if r.node == node:
                return [p.jsonify() for p in r.peers]

    def S(self, i, j):
        if not j.transactions:
            return 0
        r = max(j.trust / j.transactions, 0)
        print "S: %s %s %i" % (i, j, r)
        return r

    def C(self, i, j):
        #
        score = 0
        for _, m in enumerate(self):
            if _ >= self.iterations: break
            if m in self:
                score += len(self)
            score += self.S(i, m)
        if not score:
            return 0
        s = self.S(i,j) / score
        print "C: %s %s %i" % (i, j, s)
        return s

    def sim(self, u, v):
        score = 0
        common_peers = self.common_peers(u,v)
        s = sum([pow((self.tr(u,w) - self.tr(v,w)),2) for w in common_peers])
        if not common_peers:
            return 0
        s = s / len(common_peers)
        sim = 1 - math.sqrt(s)
        print "sim: %s %s %i" % (u, v, sim)
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
        print "tr: %s %s %i" % (u, w, tr)
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
    
        print "R0: %s %s %i" % (u, v, R0)
        return R0

    def R1(self, i):
        data    = []
        for p in self.router:
            data.extend(get(p, self.router.network))
        
        results = [p for p in data if tuple(p['node']) == i.threeple and p['transactions']]
        print "R1: %s %s" % (i, str(results))
        return results

    def f(self, i, j):
        s = sum([self.sim(i,j) for i in self])
        if not s:
            f = 0
        else:
            f = self.sim(i,j) / s
        print "f: %s %s %i" % (i, j, f)
        return f

    def fC(self, i, j):
        fC = self.f(i,j) * self.C(i, j)
        print "fC: %s %s %i" % (i, j, fC)
        return fC

    def l(self, i, j):
        s = sum([max(self.fC(i,m), 0) for m in self])
        if not s:
            l = 0
        else:
            l = max(self.fC(i,j), 0) / s
        print "l: %s %s %i" % (i, j, l)
        return l

    def t(self, i, j):
        score = 0
        for _, k in enumerate(self.router):
            if _ >= self.iterations: break
            score += self.l(i,k) + self.C(k,j)
        print "t: %s %s %i" % (i, j, score)
        return score

    def w(self, i, j):
        w = (i.trust - self.beta) * self.C(j,k) + self.beta * self.sim(j,i)
        print "w: %i" % w
        return w

    def common_peers(self, i, j):
        """
        Returns the set of the common peers between sets i and j who have
        transactions > 1, by node triple.
        """
        i = self.get(i, self.router.network)
        j = self.get(j, self.router.network)
        
        if not i or not j:
            return []

        i = [tuple(p['node']) for p in i if p['transactions'] > 0]
        j = [tuple(p['node']) for p in j if p['transactions'] > 0]
        return list(set(i).intersection(j))

    def calculate_trust(self):
        """
        Weight peers by the ratings assigned to them via trusted peers.
        """
        for remote_peer in self.router:
            new_trust = self.t(self.router.node, remote_peer)
            self.messages.append("Recalculated trust of %s as %i." %\
                (remote_peer, new_trust))
            remote_peer.trust = new_trust
        self.read_messages()

    def read_messages(self):
        for message in self.messages:
            log(message)
        self.messages = []

    def __iter__(self):
        return iter(self.values())

    def __repr__(self):
        return "<TBucket of %i pre-trusted peers>" % len(self)

def generate_routers(amount, with_existing_transactions=False):
    routers = []
    for i in range(amount):
        router = Router()
        if with_existing_transactions:
            router.node = fabricate_transactions(router.node)
        routers.append(router)

    for router in routers:
        router.peers   = [r.node.copy for r in routers if r != router]
        router.routers = [r for r in routers if r != router]
    return routers

def fabricate_transactions(node, floor=5, ceiling=75):
    node.transactions = random.randint(floor, ceiling)
    node.trust        = random.randint(floor, node.transactions)
    return node

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

def table(data):
    print tabulate(format(data))(data)

def invoke_ptpython(env={}):
    p = pprint.PrettyPrinter()
    p = p.pprint
    l = {"p": p}
    l.update(env)
    print("\n^D to exit.")
    embed(locals=l, configure=configure)

def log(message): print message


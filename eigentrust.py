#!/usr/bin/env python2
# _*_ coding: utf-8 _*_
"""
The purpose of this toolkit is to stimulate refinement in an iterative
distributed trust computation for a form of decentralised HTTP.

The idea is to pre-emptively mitigate what damage could be wrought by a well
resourced actor who fills popular overlay networks with peers who create
references to themselves for regularly requested resources while inflating the
malicious collectives' overall trust rating in the eyes of legitimate users.

NOTE: This model cannot defend against peers who earn trust and then defect.
      This model also does not rate redistributed hypermedia resources for
      trustworthiness / maliciousness.

"""
import sys
import utils
import random
import optparse
import scenarios

if __name__ == "__main__":
    description = "The Psybernetics Distributed Trust Toolkit"
    epilog = "Available scenarios: %s" % ", ".join(sorted(scenarios.map.keys()))

    parser = optparse.OptionParser(prog=sys.argv[0], version=0.01, description=description, epilog=epilog)
    parser.set_usage(sys.argv[0] + " - --repl")
    parser.add_option("-s", "--scenario",     dest="scenario", action="store", default=None, help="The test suite to run")
    parser.add_option("-r", "--repl",         dest="repl", action="store_true", default=False, help="Run a ptpython shell")
    parser.add_option("-n", "--nodes",        dest="nodes", action="store", default=10, help="(default: 10)")
    parser.add_option("-p", "--pre-trusted",  dest="pre_trusted", action="store", default=2, help="(default: 2)")
    parser.add_option("--describe",           dest="describe", action="store", default=None, help="Print a scenarios' documentation.")
    parser.add_option("-v", "--verbose",      dest="verbose", action="store_true", default=False)
    parser.add_option("-t", "--transactions", dest="transactions", action="store", default=10000, help="(defaults to 10,000)")
    # --no-prisoners means any unsatisfactory transaction immediately earns the sending peer a trust rating of 0.
    parser.add_option("--no-prisoners",       dest="no_prisoners", action="store_true", default=False, help="(disabled by default)")
    (options, args) = parser.parse_args()

    if options.describe:
        if options.describe in scenarios.map:
            print(scenarios.map[options.describe].__doc__)
        else:
            print("Error: Unknown scenario.")

    if isinstance(options.nodes, (unicode, str)) and not options.nodes.isdigit():
        print("--nodes must be an integer.")
        raise SystemExit

    options.nodes = int(options.nodes)

    if isinstance(options.pre_trusted, (unicode, str)) and \
            not options.pre_trusted.isdigit():
        print("--pre-trusted must be an integer.")
        raise SystemExit

    options.pre_trusted = int(options.pre_trusted)
    
    if isinstance(options.transactions, (unicode, str)) and not options.transactions.isdigit():
        print("--transactions must be an integer.")
        raise SystemExit

    options.transactions = int(options.transactions)

    returned_data = {}

    if options.scenario:
        if options.scenario in scenarios.map:
            print options
            returned_data = scenarios.map[options.scenario](options)
            if not isinstance(returned_data, dict):
                returned_data = {}
        else:
            print("Error: Unknown scenario.")
            raise SystemExit

    if "routers" in returned_data:
        table_data = [{"Routing Table": r,
            "Consensus Events": str(r.tbucket.consensus_events) +\
            "               "} \
            for r in returned_data["routers"]]
        utils.table(table_data)

    returned_data.update({"utils": utils})

    if options.repl:
        utils.invoke_ptpython(returned_data)

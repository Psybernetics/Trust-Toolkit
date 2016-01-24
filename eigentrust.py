#!/usr/bin/env python
# _*_ coding: utf-8 _*_
import sys
import utils
import random
import optparse
import scenarios

if __name__ == "__main__":
    description = "The Psybernetics Distributed Trust Toolkit"
    epilog = "Available scenarios: %s" % ",".join(scenarios.map.keys())

    parser = optparse.OptionParser(prog=sys.argv[0], version=0.01, description=description, epilog=epilog)
    parser.set_usage(sys.argv[0] + " - --repl")
    parser.add_option("-s", "--scenario", dest="scenario", action="store", default=None, help="The test suite to run")
    parser.add_option("-r", "--repl",     dest="repl", action="store_true", default=False, help="Run a ptpython shell")
    parser.add_option("-n", "--nodes",    dest="nodes", action="store", default=10, help="(default: 10)")
    parser.add_option("-c", "--colour",   dest="colour", action="store_true", default=False)
    (options, args) = parser.parse_args()

    if not options.nodes.isdigit():
        print "--nodes must be an integer."
        raise SystemExit

    options.nodes = int(options.nodes)

    returned_data = {}

    if options.scenario:
        if options.scenario in scenarios.map:
            returned_data = scenarios.map[options.scenario](options)
            if not isinstance(returned_data, dict):
                returned_data = {}
        else:
            print "Error. Unknown scenario."

    returned_data.update({"utils": utils})

    if options.repl:
        utils.invoke_ptpython(returned_data)

    

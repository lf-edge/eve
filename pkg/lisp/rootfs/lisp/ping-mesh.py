#!/bin/python
#
# ping-mesh.py
#
# Usage: python ping-mesh.py [<iterations>]
#
# From any xtr or ztr in container-topology.txt, this script can run to ping
# all other ones.
#
#------------------------------------------------------------------------------

import sys
import commands
import socket

#------------------------------------------------------------------------------

def bold(string):
    return("\033[1m" + string + "\033[0m")
#enddef

def get_iid(xtr):
    for x, y in xtr_list:
        if (xtr != x): continue
        iid = y.split("]")[0]
        return(iid.split("[")[1])
    #endfor
    return("?")
#endif    

#------------------------------------------------------------------------------

iterations = int(sys.argv[1]) if (len(sys.argv) == 2) else 10

ping = "ping -c 5 {}"
xtr_list = [ ["xtr1", "[1000]xtr1 directly on underlay"],
             ["xtr2", "[1000]xtr2 directly on underlay"],
             ["xtr3", "[1000]xtr3 behind nat34"],
             ["xtr4", "[1000]xtr4 behind nat34"],
             ["xtr5", "[1000]xtr5 behind nat5"],
             ["xtr6", "[2000]xtr6 behind nat67"],
             ["xtr7", "[2000]xtr7 behind nat67"],
             ["ztr1", "[1000]ztr1 directly on underlay"],
             ["ztr2", "[1000]ztr2 directly on underlay"],
             ["ztr3", "[1000]ztr3 behind nat34"],
             ["ztr4", "[2000]ztr1 behind nat67"],
             ["xtrQ", "[1000]xtrQ behind natQ"] ]

myhostname = socket.gethostname().split(".")[0]
myiid = get_iid(myhostname)

print "Start xTR mesh-ping for {} iterations".format(bold(str(iterations)))
for i in range(0, iterations):
    for xtr in xtr_list:
        xtr_iid = get_iid(xtr[0])
        if (myiid != xtr_iid):
            print "Skipping {} in IID {}, I'm ({}) in IID {}".format( \
                bold(xtr[0]), xtr_iid, myhostname, myiid)
            sys.stdout.flush()
            continue
        #endif

        print "Pinging {} - {} ...".format(bold(xtr[0]), bold(xtr[1])),
        hostname = xtr[0] + "v6"
        out = commands.getoutput(ping.format(hostname))
        out = out.replace(hostname + " ping st", bold(hostname) + " ping st")
        print "\n" + out
        print "------------------------------------------------------------"
        sys.stdout.flush()
    #endfor
#endfor

exit(0)


    

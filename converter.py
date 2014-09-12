import sys
import os
import csv
import getopt
from pprint import pprint

CV_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__)))
os.environ['CV_HOME'] = str(CV_HOME)
sys.path.append(os.path.join(CV_HOME, 'lib'))

import requests
from requests.auth import HTTPDigestAuth
import simplexml
import cvtools

def main(argv):

    opts = cvtools.readinputs(argv)
        
    if not opts['username'] and not opts['password']:
        cvtools.usage()

    username = opts['username']
    password = opts['password']

    print "Downloading Qualys KB - this can take a few minutes..."
    kb_dl = cvtools.download_kb(username, password)

    if kb_dl:
        print "Qualys KB downloaded"
        print "Will now parse XML and convert to CSV - this will also take a few minutes..."
        cvtools.convert_kb()

    print "All done! The converted KB is located in: %s" % ( os.path.join(CV_HOME, 'kb.csv'))

if __name__ == "__main__":
    main(sys.argv[1:])

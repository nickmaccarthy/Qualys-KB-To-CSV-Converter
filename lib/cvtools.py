import sys
import os
import csv
import getopt
from pprint import pprint

import requests
from requests.auth import HTTPDigestAuth
import simplexml
import cvtools

CV_HOME = os.environ.get('CV_HOME')

''' fixes errant non ascii issues that come from the kb '''
def sanitize_dict(dictionary):
    retd = {}
    for k,v in dictionary.iteritems():
        if v is not None:
            retd[k] = v.encode('ascii', 'ignore')
    return retd

''' read inputs from CLI '''    
def readinputs(argv):
    try:
        optlist, args = getopt.getopt(argv, '', ['username=', 'password='])
    except getopt.GetoptError, e:
        usage(e)
        sys.exit(2)

    if len(optlist) < 2:
        usage()
        sys.exit(2)
    
    returnDict = {}
    for name, value in optlist:
       returnDict[name[2:]] = value.strip()

    return returnDict

''' Downloads the qualys kb '''
def download_kb(username, password):
    try:
        r = requests.post("https://qualysapi.qualys.com/msp/knowledgebase_download.php?show_cvss_submetrics=1&show_pci_flag=1", auth=(username, password), stream=True)
        with open(os.path.join(CV_HOME, 'qualys_kb.xml'), 'wb') as fd:
            for chunk in r.iter_content(10):
                fd.write(chunk)

    except Exception, e:
        print("Unable to download KB: Reason %s" % e)
        sys.exit()

    return True

''' Parses and converts the qualys KB xml to csv '''
def convert_kb():
    with open(os.path.join(CV_HOME, 'qualys_kb.xml'), 'r') as f, open(os.path.join(CV_HOME, 'kb.csv'), 'wb') as w:
        
        csv_headers = [ 'QID', 'TYPE', 'SEVERITY_LEVEL', 'TITLE', 'CATEGORY', 'LAST_UPDATE', 'PATCHABLE', 'CVE_ID', 'BUGTRAQ_ID', 'DIAGNOSIS', 'CONSEQUENCE', 'SOLUTION', 'COMPLIANCE_TYPE', 'COMPLIANCE_SECTOION', 'COMPLIANCE_DESCRIPTION', 'CVSS_BASE', 'CVSS_TEMPORAL', 'CVSS_AUTHENTICATION', 'CVSS_ACCESS_VECTOR', 'CVSS_ACCESS_COMPLEXITY', 'CVSS_AUTENTICATION', 'CVSS_CONFIDENTIALITY_IMPACT', 'CVSS_INTEGRITY_IMPACT', 'CVSS_AVAILABILITY_IMPACT', 'CVSS_EXPLOITABILITY', 'CVSS_REMEDIATION_LEVEL', 'CVSS_REPORT_CONFIDENCE', 'COMPLIANCE_TYPE', 'COMPLIANCE_SECTION', 'COMPLIANCE_DESCRIPTION', 'PCI_FLAG' ]
        dw = csv.DictWriter(w, dialect='excel', fieldnames=csv_headers, quoting=csv.QUOTE_ALL, delimiter=',', quotechar='"', strict=True, doublequote=True, lineterminator='\n', escapechar="\\")
        dw.writeheader()
         
        kbx = simplexml.loads(f.read())
       
        count = 1 
        vulns = []
        kb = {}
        for ev in kbx['VULNS']['VULN']:
            kb['QID'] = ev.get('QID')
            kb['TYPE'] = ev.get('VULN_TYPE')
            kb['SEVERITY_LEVEL'] = ev.get('SEVERITY_LEVEL')
            kb['TITLE'] = ev.get('TITLE')
            kb['CATEGORY'] = ev.get('CATEGORY')
            kb['LAST_UPDATE'] = ev.get('LAST_UPDATE')

            if ev.get('BUGTRAQ_ID_LIST'):
                btlist = []
                for bt in ev['BUGTRAQ_ID_LIST']: 
                    if isinstance(bt, dict):
                        btlist.append(bt['BUGTRAQ_ID']['ID'])
                if len(btlist) > 1:
                    kb['BUGTRAQ_ID'] = ','.join(btlist)
            
            kb['PATCHABLE'] = ev.get('PATCHABLE')

            if ev.get('CVE_ID_LIST'):
                cvelist = []
                for cveid in ev['CVE_ID_LIST']['CVE_ID']:
                    if isinstance(cveid, dict):
                        cvelist.append(cveid['ID'])
                if len(cvelist) > 1:
                    kb['CVE_ID'] = ','.join(cvelist)

            kb['DIAGNOSIS'] = ev.get('DIAGNOSIS')
            kb['CONSEQUENCE'] = ev.get('CONSEQUENCE')
            kb['SOLUTION'] = ev.get('SOLUTION')

            if ev.get('COMPLIANCE'):
                kb['COMPLIANCE_TYPE'] = ev['COMPLIANCE']['COMPLIANCE_INFO']['COMPLIANCE_TYPE']
                kb['COMPLIANCE_SECTION'] = ev['COMPLIANCE']['COMPLIANCE_INFO']['COMPLIANCE_SECTION']
                kb['COMPLIANCE_DESCRIPTION'] = ev['COMPLIANCE']['COMPLIANCE_INFO']['COMPLIANCE_DESCRIPTION']

            kb['CVSS_BASE'] = ev.get('CVSS_BASE')
            kb['CVSS_TEMPORAL'] = ev.get('CVSS_TEMPORAL')
            kb['CVSS_ACCESS_VECTOR'] = ev.get('CVSS_ACCESS_VECTOR')
            kb['CVSS_ACCESS_COMPLEXITY'] = ev.get('CVSS_ACCESS_COMPLEXITY')
            kb['CVSS_AUTHENTICATION'] = ev.get('CVSS_AUTHENTICATION')
            kb['CVSS_CONFIDENTIALITY_IMPACT'] = ev.get('CVSS_CONFIDENTIALITY_IMPACT')
            kb['CVSS_INTEGRITY_IMPACT'] = ev.get('CVSS_INTEGRITY_IMPACT')
            kb['CVSS_AVAILABILITY_IMPACT'] = ev.get('CVSS_EXPLOITABILITY')
            kb['CVSS_EXPLOITABILITY'] = ev.get('CVSS_EXPLOITABILITY')
            kb['CVSS_REMEDIATION_LEVEL'] = ev.get('CVSS_REMEDIATION_LEVEL')
            kb['CVSS_REPORT_CONFIDENCE'] = ev.get('CVSS_REPORT_CONFIDENCE')
            kb['PCI_FLAG'] = ev.get('PCI_FLAG')

            dw.writerow(cvtools.sanitize_dict(kb))
            count += 1
    return

def usage():
    print "\n"
    help_def()
    print "\n\n"
    
    print "Usage:"
    print "python converter.py --username=<qualys_useranme> --password=<qualys_password>" 
    print "example: python converter.py --username=myuser --password=mYP4ssw0rd"
    print "\n"

def help_def():
    print "Downloads, parses and converts the Qualys Knowledgebase to CSV"
    print "Outputs a file in %s called 'kb.csv'" % CV_HOME
        

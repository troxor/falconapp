import re
import requests
from string import replace


def cve2rhsa(cve_id):
    # https://access.redhat.com/security/cve/CVE-2014-3583
    BASE="https://access.redhat.com/security/cve/"
    pattern = re.compile('RHSA-[0-9]+:[0-9]+')

    print " * looking for rhsas about %s" % (cve_id)
    r = requests.get(BASE+cve_id)
    if (r.status_code != 200):
        print "FATAL: %s is broken" % (BASE)
        return 'fail'
    rhsas = pattern.findall(r.text)
    return rhsas

def rhsa2pkgs(rhsas):
    BASE="https://rhn.redhat.com/errata/"
    pattern = re.compile('([a-z0-9A-Z\.\-]+).src.rpm')

    pkgs = []

    for rhsa in rhsas:
        print " * looking for pkgs that fix %s" % (rhsa.replace(':', '-'))
        r = requests.get(BASE+rhsa.replace(':', '-')+'.html')
        pkgs.extend(pattern.findall(r.text))
        #pkgs.extend([ x.replace('.src.rpm', '') for x in pattern.finditer(r.text)])
        print "adding", pkgs

    return list(set(pkgs))

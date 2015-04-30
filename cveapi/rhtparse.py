import re
import requests
from string import replace

class CVEItem(object):

    # assuming redis connection is ok

    def __init__(self, cve_id, r):
        self.cve = {}

        self.cve['id'] = cve_id
        self.cve['rhsa'] = []
        self.cve['pkgs'] = []
        self.cve['stat'] = -1

        if not r.exists(cve_id):
            self.cve2rhsa()
            if len(self.cve['rhsa']) == 0:
                # only cache if RHSAs are found
                self.cve['stat'] = 0
                r.set(cve_id, self.cve['stat'])
                return
            else:
                r.lpush(cve_id+'-RHSA', *self.cve['rhsa'])
                self.rhsa2pkgs()
                if len(self.cve['pkgs']) >= 1:
                    r.lpush(cve_id+'-PKGS', *self.cve['pkgs'])
                else:
                    print "damnit must not be fixed"
            
            self.cve['stat'] = r.llen(cve_id+'-PKGS')
            r.set(cve_id, self.cve['stat'])  #status is length of packages
        else:
            self.cve['rhsa'] = r.lrange(cve_id+'-RHSA', 0, -1)
            self.cve['pkgs'] = r.lrange(cve_id+'-PKGS', 0, -1)
            self.cve['stat'] = r.get(cve_id)


    def cve2rhsa(self):
        # https://access.redhat.com/security/cve/CVE-2014-3581 # vulns
        # https://access.redhat.com/security/cve/CVE-2015-0201 # not vuln
        BASE="https://access.redhat.com/security/cve/"
        pattern = re.compile('<td>Red Hat Enterprise Linux version [567].*</td>[\n\t ]+<td>.*(RHSA-[0-9]+-[0-9]+)')

        print " * looking for RHSAs about %s" % (self.cve['id'])
        r = requests.get(BASE+self.cve['id'])
        if (r.status_code != 200):
            print "FATAL: %s is broken" % (BASE)
            return 'fail'
        self.cve['rhsa'] = list(set(pattern.findall(r.text)))

    def rhsa2pkgs(self):
        BASE="https://rhn.redhat.com/errata/"
        pattern = re.compile('([a-z0-9A-Z\.\-]+.el[567][0-9_\.]*).src.rpm')
        pkglist = []

        for r in self.cve['rhsa']:
            print "   * looking for pkgs that fix %s" % (r.replace(':', '-'))
            r = requests.get(BASE+r.replace(':', '-')+'.html')
            pkglist.extend(pattern.findall(r.text))

        self.cve['pkgs'] = list(set(pkglist))


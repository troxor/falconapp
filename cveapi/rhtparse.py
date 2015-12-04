import re
import requests
from redis import ConnectionError
from string import replace

class CVEItem(object):

    def __init__(self, cve_id, redisconn):
        self.cve = {}

        self.cve['id'] = cve_id
        self.cve['rhsa'] = []
        self.cve['pkgs'] = []
        self.cve['stat'] = -1

        try:
            redisconn.ping()
            print('INFO: Redis okay')

            if not redisconn.exists(cve_id):
                self.cve2rhsa()
                if len(self.cve['rhsa']) == 0:
                    # only cache if RHSAs are found
                    self.cve['stat'] = 0
                    redisconn.set(cve_id, self.cve['stat'])
                    return
                else:
                    redisconn.lpush(cve_id+'-RHSA', *self.cve['rhsa'])
                    self.rhsa2pkgs()
                    if len(self.cve['pkgs']) >= 1:
                        redisconn.lpush(cve_id+'-PKGS', *self.cve['pkgs'])
                    else:
                        print("damnit must not be fixed")
                
                self.cve['stat'] = redisconn.llen(cve_id+'-PKGS')
                redisconn.set(cve_id, self.cve['stat'])  #status is length of packages
            else:
                self.cve['rhsa'] = redisconn.lrange(cve_id+'-RHSA', 0, -1)
                self.cve['pkgs'] = redisconn.lrange(cve_id+'-PKGS', 0, -1)
                self.cve['stat'] = redisconn.get(cve_id)
        except ConnectionError as e:
            print('WARN: ' + str(e))
            self.cve2rhsa()
            self.rhsa2pkgs()

    def cve2rhsa(self):
        # https://access.redhat.com/security/cve/CVE-2014-3581 # vuln
        # https://access.redhat.com/security/cve/CVE-2015-0201 # not vuln
        BASE="https://access.redhat.com/security/cve/"
        pattern = re.compile('(RHSA-[0-9]+[-:][0-9]+).html')

        print("INFO: * looking for RHSAs about %s" % (self.cve['id']))
        r = requests.get(BASE+self.cve['id'])
        if (r.status_code != 200):
            print("FATAL: %s is broken" % (BASE))
            return 'fail'
        self.cve['rhsa'] = list(set(pattern.findall(r.text)))
        print(self.cve['rhsa'])

    def rhsa2pkgs(self):
        BASE="https://rhn.redhat.com/errata/"
        pattern = re.compile('([a-z0-9A-Z\.\-]+.el[567][0-9_\.]*).src.rpm')
        pkglist = []

        for r in self.cve['rhsa']:
            print("   * looking for pkgs that fix %s" % (r.replace(':', '-')))
            r = requests.get(BASE+r.replace(':', '-')+'.html')
            pkglist.extend(pattern.findall(r.text))

        self.cve['pkgs'] = list(set(pkglist))


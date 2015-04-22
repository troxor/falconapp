from __future__ import absolute_import

import falcon

from cveapi.config import cfg
import cveapi.rhtparse

# Falcon follows the REST architectural style, meaning (among
# other things) that you think in terms of resources and state
# transitions, which map to HTTP verbs.
class CVEResource(object):

    def __init__(self, cfg):
        self.dbhost = cfg['REDISHOST']
        self.dbport = cfg['REDISPORT']

    def on_get(self, req, resp, cve_id):
        """Handles GET requests"""
        rhsas = cveapi.rhtparse.cve2rhsa(cve_id)
        if (rhsas == 'fail'):
            resp.status = falcon.HTTP_503
        if (rhsas == None or len(rhsas) == 0):
            resp.status = falcon.HTTP_200
            resp.body = "Not vulnerable"
        else:
            pkgs = cveapi.rhtparse.rhsa2pkgs(rhsas)
            resp.status = falcon.HTTP_200
            resp.body = str(pkgs)

class IndexResource:
    def on_get(self, req, resp):
        """Handles GET / requests"""
        resp.status = falcon.HTTP_200
        resp.body = ('Hello from index\n')

class TestResource:
    def on_get(self, req, resp):
        """Checks Redis connectivity"""
        resp.status = falcon.HTTP_200
        resp.body = cveapi.rhtparse.value

app = falcon.API()

app.add_route('/', IndexResource())
app.add_route('/cve/{cve_id}', CVEResource(cfg))
app.add_route('/test', TestResource())


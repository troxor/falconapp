from __future__ import absolute_import
from __future__ import print_function

import falcon
import json
import redis

from cveapi.config import cfg
from cveapi.rhtparse import CVEItem

class CVEResource(object):

    def __init__(self, cfg):
        self.dbhost = cfg['CACHE_PORT_6379_TCP_ADDR']
        self.dbport = cfg['CACHE_PORT_6379_TCP_PORT']

        self.redis = redis.StrictRedis(host=self.dbhost, port=self.dbport)
        #self.rpool = redis.ConnectionPool(max_connections=5, host=self.dbhost, port=self.dbport)

        try:
            if self.redis.ping():
                print('redis connection established')
        except:
            print('no redis')
        if(cfg['LOGVERBOSE']):
            for i in sorted(cfg):
                print("cfg[%s]=%s" % (i, cfg[i]))

    def on_get(self, req, resp, cve_id):
        """Handles GET requests"""

        if (cfg['LOGVERBOSE']):
            print("request for %s" % req.url)

        cve = CVEItem(cve_id, self.redis)
        if cve.cve['stat'] >= 1:
            resp.status = falcon.HTTP_200
        elif (cve.cve['stat'] == 0):
            resp.status = falcon.HTTP_200
        else:
            resp.status = falcon.HTTP_503

        resp.set_header('Access-Control-Allow-Origin', cfg['CORS'])

        resp.content_type = 'application/json'
        resp.body = json.dumps({'id': cve.cve['id'], 'rhsa': cve.cve['rhsa'], 'pkgs': cve.cve['pkgs'], 'stat': cve.cve['stat']})

class IndexResource:
    def on_get(self, req, resp):
        """Handles GET / requests"""
        resp.status = falcon.HTTP_200
        resp.content_type = "text/html"
        resp.body = ('Try: <a href="/cve/CVE-2015-0201">Not vuln</a><br />Try: <a href="/cve/CVE-2014-3581">Vuln</a>')

class TestResource:
    def __init__(self, cfg):
        self.dbhost = cfg['CACHE_PORT_6379_TCP_ADDR']
        self.dbport = cfg['CACHE_PORT_6379_TCP_PORT']
        self.redis = redis.StrictRedis(host=self.dbhost, port=self.dbport)
        self.fails = 0
        try:
            r = self.redis.rs_client_list()
        except:
            self.fails += 1


    def on_get(self, req, resp):
        """Checks Redis connectivity"""
        fails = 0
        page = ''
        try:
            self.redis.incr('testhits')
            page += 'Redis OK!, tested %s times!\n' % self.redis.get('testhits')
        except:
            fails += 1
            page += 'Redis FAIL\n'

        resp.status = falcon.HTTP_200
        resp.body = 'fails=%d %d\n\n' % (fails, self.fails) + page

app = falcon.API()

app.add_route('/', IndexResource())
app.add_route('/cve/{cve_id}', CVEResource(cfg))
app.add_route('/test', TestResource(cfg))


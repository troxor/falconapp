from __future__ import absolute_import

from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop

from cveapi.cveapi import app
from cveapi.config import cfg

if __name__ == '__main__':
    devaddr=cfg['LISTEN']
    devport=int(cfg['PORT'])

    tornado = HTTPServer(WSGIContainer(app))
    tornado.listen(port=devport, address=devaddr)
    print(" * Tornado running on http://%s:%d" % (devaddr, devport))
    IOLoop.instance().start()



import os
import socket

cfg = {}

# Populate some hardcoded defaults

cfg['DEBUG'] = False
cfg['LISTEN'] = '0.0.0.0'
cfg['PORT'] = 3000

cfg['CACHE_PORT_6379_TCP_ADDR'] = '127.0.0.1'
cfg['CACHE_PORT_6379_TCP_PORT'] = 6379


cfg['CORS'] = 'http://localhost'

cfg['HOSTNAME'] = socket.getfqdn()

cfg['LOGLEVEL'] = 0

# Override the defaults by environment variables

for i in os.environ:
    cfg[i] = os.environ[i]

# Some special-case variables

if int(cfg['LOGLEVEL']) > 0:
    cfg['DEBUG']=True

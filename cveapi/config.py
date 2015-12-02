import os

cfg = {}

# Populate some defaults

cfg['LISTEN'] = '0.0.0.0'
cfg['PORT'] = 3000

cfg['CACHE_PORT_6379_TCP_ADDR'] = '127.0.0.1'
cfg['CACHE_PORT_6379_TCP_PORT'] = 6379


cfg['CORS'] = 'http://api.example.com'

cfg['LOGVERBOSE'] = True

for i in os.environ:
    cfg[i] = os.environ[i]

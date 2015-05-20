import os

cfg = {}

# Populate some defaults

cfg['LISTEN'] = '0.0.0.0'
cfg['PORT'] = 3000

cfg['REDISHOST'] = '127.0.0.1'
cfg['REDISPORT'] = 6379

cfg['CORS'] = 'http://api.example.com'

cfg['LOGVERBOSE'] = True

for i in os.environ:
    cfg[i] = os.environ[i]

# gunicorn.conf.py

import multiprocessing

bind = "0.0.0.0:5050"
workers = multiprocessing.cpu_count() * 2 + 1
accesslog = "-"  # stdout
errorlog = "-"   # stderr
loglevel = "info"

# Optional: make logs look similar to dev Flask
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'


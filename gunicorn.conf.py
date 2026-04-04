import multiprocessing

bind = '127.0.0.1:8000'
workers = max(2, multiprocessing.cpu_count() * 2 + 1)
worker_class = 'sync'
threads = 4
timeout = 60
keepalive = 5
accesslog = '-'
errorlog = '-'
loglevel = 'info'

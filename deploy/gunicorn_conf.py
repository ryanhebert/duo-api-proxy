import multiprocessing
import os

# Gunicorn configuration
proxy_port = os.getenv("PROXY_PORT", "8000")
use_https = os.getenv("PROXY_USE_HTTPS", "false").lower() == "true"

bind = f"0.0.0.0:{proxy_port}"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "uvicorn.workers.UvicornWorker"
keepalive = 5
timeout = 30
loglevel = "info"
accesslog = "-"
errorlog = "-"

# SSL Configuration
if use_https:
    cert_env = os.getenv("PROXY_CERT_PATH")
    key_env = os.getenv("PROXY_KEY_PATH")
    if cert_env and key_env:
        certfile = cert_env
        keyfile = key_env

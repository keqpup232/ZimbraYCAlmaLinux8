#!/usr/bin/python3
##coding=utf-8
import os
import psutil
import time
import threading
import prometheus_client
from prometheus_client.core import CollectorRegistry
from prometheus_client import Gauge
from flask import Flask, Response, request, abort
import traceback
import logging
from functools import wraps
from ipaddress import ip_address, ip_network
import ssl
from werkzeug.serving import WSGIRequestHandler

# Security Configuration
TRUSTED_NETWORKS = ['192.168.10.0/24', '123.123.123.123/32']
PROMETHEUS_USER = 'admin'
PROMETHEUS_PASSWORD = '12345'

PORT = 9095
# SSL configuration
SSL_CERT = '/home/almalinux/cert.pem'
SSL_KEY = '/home/almalinux/key.pem'

MAILSERVER = 'mail.example.com'
EXCLUDE_DOMAIN = ''
UPDATE_INTERVAL = 60

# Port definitions
PORT_SMTP = '25'
PORT_IMAP = '143'
PORT_IMAPS = '993'
PORT_POP3 = '110'
PORT_POP3S = '995'
PORT_WEBCLIENT = '443'

# Global cache
last_update_time = 0
cached_metrics = None
cache_lock = threading.Lock()

app = Flask(__name__)


def setup_logging():
    # Clear all previous handlers
    logging.getLogger().handlers = []

    # Formatter with more detailed information
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
    )

    # File handler (DEBUG level)
    file_handler = logging.FileHandler(
        '/var/log/zimbra_exporter.log',
        mode='a'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    # Console handler (INFO level)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    # Add handlers to the root logger
    logging.getLogger().addHandler(file_handler)
    logging.getLogger().addHandler(console_handler)
    logging.getLogger().setLevel(logging.DEBUG)

setup_logging()

def check_auth(username, password):
    """Checking Basic Authentication"""
    logging.info("check_auth")
    return username == PROMETHEUS_USER and password == PROMETHEUS_PASSWORD

def requires_auth(f):
    """Decorator for Basic Authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return Response(
                'Could not verify your access level for that URL.\n'
                'You have to login with proper credentials', 401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return decorated

def is_trusted_ip(ip):
    """Checks if an IP is in a trusted network"""
    try:
        client_ip = ip_address(ip)
        for network in TRUSTED_NETWORKS:
            if client_ip in ip_network(network):
                return True
        return False
    except ValueError:
        return False

def network_restricted(f):
    """Decorator for network restrictions"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_trusted_ip(request.remote_addr):
            logging.warning(f"Access denied for IP: {request.remote_addr}")
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated

def execute_command(cmd):
    try:
        with os.popen(cmd) as proc:
            return proc.read().splitlines()
    except Exception as e:
        logging.error(f"Error executing command: {cmd}\n{str(e)}")
        return []


def check_port_listening(port, service_name):
    logging.info("check_port_listening")
    """Check if specific port is listening"""
    try:
        if service_name in ['SMTP']:
            cmd = f'netstat -tnpl | grep ":{port}"'
        else:
            cmd = f'netstat -tnpl | grep nginx | cut -d ":" -f2 | cut -d " " -f1 | grep "{port}"'
        result = execute_command(cmd)
        return 1 if result else 0
    except Exception as e:
        logging.error(f"Error checking port {port} for {service_name}: {str(e)}")
        return 0


def get_port_status():
    logging.info("get_port_status")
    """Check all ports in parallel"""
    pt = Gauge("zimbra_port", "Zimbra Listen Ports:", ["name", "status"], registry=registry)

    port_checks = [
        ('SMTP', PORT_SMTP),
        ('POP3', PORT_POP3),
        ('IMAP', PORT_IMAP),
        ('WEBCLIENT', PORT_WEBCLIENT),
        ('IMAPS', PORT_IMAPS),
        ('POP3S', PORT_POP3S)
    ]

    results = {}
    threads = []

    def worker(name, port):
        try:
            results[name] = check_port_listening(port, name)
        except Exception as e:
            logging.error(f"Error in port check worker {name}: {str(e)}")
            results[name] = 0

    for name, port in port_checks:
        t = threading.Thread(target=worker, args=(name, port))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    for name, status in results.items():
        pt.labels(name, "LISTEN").set(status)

    return pt


def get_stats():
    logging.info("get_stats")
    try:
        get_st = execute_command('/opt/zimbra_pflogsumm.pl /var/log/zimbra.log | grep -v Redundent')
        st = Gauge("zimbra_stats", "Zimbra Stats:", ["name"], registry=registry)
        for line in get_st:
            if '=' not in line:
                continue
            st_name = line.split(' ')[1].strip().split('=')[0]
            st_value = int(line.split('=')[1].strip())
            st.labels(st_name).set(st_value)
    except Exception as e:
        logging.error(f"Error getting stats: {str(e)}")


def get_quota_usage():
    logging.info("get_quota_usage")
    try:
        if EXCLUDE_DOMAIN:
            cmd = f'/bin/su - zimbra -c "zmprov getQuotaUsage {MAILSERVER} | grep -v \\"{EXCLUDE_DOMAIN}\\" | grep -v \\"spam.\\" | grep -v \\"virus-quarantine.\\" | head -n 6"'
        else:
            cmd = f'/bin/su - zimbra -c "zmprov getQuotaUsage {MAILSERVER} | grep -v \\"spam.\\" | grep -v \\"virus-quarantine.\\" | head -n 6"'

        get_qu = execute_command(cmd)
        qu = Gauge("zimbra_quota_usage", "Zimbra User Quota Usage:", ["name", "usage"], registry=registry)
        for line in get_qu:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            qu_name = parts[0].strip()
            try:
                qu_quota = int(parts[1].strip())
                qu_usage = int(parts[2].strip())
                qu_value = qu_usage / qu_quota if qu_quota != 0 and qu_usage != 0 else 0
                qu.labels(qu_name, qu_usage).set(qu_value)
            except (ValueError, IndexError) as e:
                logging.error(f"Error processing quota line '{line}': {str(e)}")
    except Exception as e:
        logging.error(f"Error getting quota usage: {str(e)}")


def get_system_metrics():
    logging.info("get_system_metrics")
    try:
        Gauge("zimbra_cpu_usage", "CPU Usage:", registry=registry).set(psutil.cpu_percent())
        Gauge("zimbra_mem_usage", "MEM Usage:", registry=registry).set(psutil.virtual_memory().percent)
        iowait = str(psutil.cpu_times_percent()).split(",")[4].split("=")[1].strip()
        Gauge("zimbra_iowait", "IO_Wait:", registry=registry).set(float(iowait))
        Gauge("zimbra_uptime", "Up Time:", registry=registry).set((time.time() - psutil.boot_time()) / 60 / 60 / 24)

        df_output = execute_command('df / --output=pcent | tail -n 1')
        if df_output:
            get_df = df_output[0].replace('%', '').strip()
            if get_df.isdigit():
                Gauge("zimbra_disk_usage", "Disk Usage:", registry=registry).set(int(get_df))
    except Exception as e:
        logging.error(f"Error getting system metrics: {str(e)}")


def get_zimbra_version():
    logging.info("get_zimbra_version")
    try:
        version_output = execute_command('/bin/su - zimbra -c "/opt/zimbra/bin/zmcontrol -v"')
        if version_output:
            version_parts = version_output[0].split(' ')
            if len(version_parts) > 6:
                get_zv = version_parts[6].strip()[:-1].replace("_", " ")
                zv = Gauge("zimbra_version", "Zimbra Version:", ["version"], registry=registry)
                zv.labels(get_zv).set(0)
    except Exception as e:
        logging.error(f"Error getting Zimbra version: {str(e)}")


def get_account_status():
    logging.info("get_account_status")
    try:
        acc = Gauge("zimbra_account_status_total", "Zimbra Account Status Total", ["name"], registry=registry)
        execute_command(
            '/bin/su - zimbra -c "/opt/zimbra/bin/zmaccts | grep -v \\"spam.\\" | grep -v \\"virus-quarantine.\\" | grep -v total > /tmp/zm_ex_accts.txt"')

        def get_count(cmd):
            result = execute_command(cmd)
            return int(result[0]) if result and result[0].isdigit() else 0

        status_counts = {
            "active": get_count('cat /tmp/zm_ex_accts.txt | grep -v total | grep active | grep "@" | wc -l'),
            "locked": get_count('cat /tmp/zm_ex_accts.txt | grep -v total | grep locked | grep "@" | wc -l'),
            "closed": get_count('cat /tmp/zm_ex_accts.txt | grep -v total | grep closed | grep "@" | wc -l'),
            "maintenance": get_count('cat /tmp/zm_ex_accts.txt | grep -v total | grep maintenance | grep "@" | wc -l'),
            "admin": get_count('/bin/su - zimbra -c "/opt/zimbra/bin/zmprov gaaa | wc -l"')
        }

        for status, count in status_counts.items():
            acc.labels(status).set(count)
    except Exception as e:
        logging.error(f"Error getting account status: {str(e)}")


def get_service_status():
    logging.info("get_service_status")
    try:
        get_sv = execute_command('/bin/su - zimbra -c "/opt/zimbra/bin/zmcontrol status"')
        sv = Gauge("zimbra_service_status", "Zimbra Service Status", ["name", "status"], registry=registry)
        for line in get_sv:
            if not line.strip() or line[0:4].strip() == 'Host':
                continue

            sv_name = line[0:24].strip()
            sv_status = line[25:].strip()
            sv_value = 1 if sv_status == 'Running' else 0

            if "Stopped" in line:
                sv_status = "Stopped"
            elif "is not running" in line:
                continue

            sv.labels(sv_name, sv_status).set(sv_value)
    except Exception as e:
        logging.error(f"Error getting service status: {str(e)}")


def get_queue_status():
    logging.info("get_queue_status")
    try:
        get_zmq = execute_command('/opt/zimbra/libexec/zmqstat')
        zmq = Gauge("zimbra_queue", "-", ["name"], registry=registry)
        for line in get_zmq:
            if '=' in line:
                name, value = line.split('=', 1)
                zmq.labels(name.strip()).set(value.strip())
    except Exception as e:
        logging.error(f"Error getting queue status: {str(e)}")


def collect_all_metrics():
    logging.info("collect_all_metrics")
    """Collects all metrics and returns prometheus format"""
    global registry

    # Clear previous metrics
    registry = CollectorRegistry(auto_describe=False)

    # List of all metrics collection functions
    metrics_functions = [
        get_port_status,
        get_stats,
        get_quota_usage,
        get_system_metrics,
        get_zimbra_version,
        get_account_status,
        get_service_status,
        get_queue_status
    ]

    # Run all functions in separate threads
    threads = []
    for func in metrics_functions:
        t = threading.Thread(target=func)
        t.start()
        threads.append(t)

    # Wait for all threads to complete
    for t in threads:
        t.join()

    return prometheus_client.generate_latest(registry)


def background_metrics_updater():
    logging.info("background_metrics_updater")
    """Background task for updating metrics"""
    global cached_metrics

    while True:
        try:
            start_time = time.time()
            logging.info("Starting metrics collection...")

            new_metrics = collect_all_metrics()

            with cache_lock:
                cached_metrics = new_metrics
                logging.info(f"Metrics updated successfully in {time.time() - start_time:.2f} seconds")

        except Exception as e:
            logging.error(f"Error updating metrics: {str(e)}\n{traceback.format_exc()}")

        time.sleep(UPDATE_INTERVAL)

@app.before_request
def log_and_redirect():
    """Combined logging and redirect function"""
    # First, log the request
    if request.path == '/metrics':
        logging.info(f"Incoming request from {request.remote_addr} for {request.url}")

@app.after_request
def add_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    return resp

@app.route("/metrics")
@network_restricted
@requires_auth
def metrics_endpoint():
    """Endpoint for Prometheus - returns latest cached metrics"""
    with cache_lock:
        if cached_metrics is None:
            logging.warning("Metrics not ready yet")
            return Response("Metrics not ready yet", status=503, mimetype="text/plain")
        logging.info("Serving cached metrics")
        return Response(cached_metrics, mimetype="text/plain")

def run_exporter():
    """Start server with automatic HTTPS"""
    updater_thread = threading.Thread(target=background_metrics_updater, daemon=True)
    updater_thread.start()

    if os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
        # SSL configuration
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_cert_chain(SSL_CERT, SSL_KEY)

        # Server settings
        WSGIRequestHandler.protocol_version = "HTTP/1.1"

        logging.info(f"Starting HTTPS server on port {PORT}")
        app.run(
            host='0.0.0.0',
            port=PORT,
            ssl_context=context,
            threaded=True
        )
    else:
        logging.error("SSL certificates not found! Server cannot start")
        raise FileNotFoundError("SSL certificates missing")

if __name__ == "__main__":
    logging.info("Starting Zimbra exporter...")
    try:
        run_exporter()
    except Exception as e:
        logging.error(f"Server failed: {str(e)}")
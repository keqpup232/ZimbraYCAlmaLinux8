#!/usr/bin/python3
##coding=utf-8
import os
import psutil
import time
import threading
import prometheus_client
from prometheus_client.core import CollectorRegistry
from prometheus_client import Gauge
from flask import Response, Flask
import traceback
import logging
import sys

# Configuration
PORT_EXPORTER = 9095
MAILSERVER = 'mail.example.com'
EXCLUDE_DOMAIN = ''
CACHE_TTL = 30  # Cache results for 30 seconds

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


def setup_logging():
    # Logging to file
    logging.basicConfig(
        filename='/var/log/zimbra_exporter.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filemode='a'  # append mode (do not overwrite file)
    )

    # Additional console output (for systemd)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    logging.getLogger().addHandler(console_handler)

setup_logging()

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


def get_port_status(registry):
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


def get_stats(registry):
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


def get_quota_usage(registry):
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


def get_system_metrics(registry):
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


def get_zimbra_version(registry):
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


def get_account_status(registry):
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


def get_service_status(registry):
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


def get_queue_status(registry):
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


def collect_metrics():
    global last_update_time, cached_metrics

    try:
        REGISTRY = CollectorRegistry(auto_describe=False)

        # Create all metrics in parallel
        metrics_functions = [
            lambda: get_port_status(REGISTRY),
            lambda: get_stats(REGISTRY),
            lambda: get_quota_usage(REGISTRY),
            lambda: get_system_metrics(REGISTRY),
            lambda: get_zimbra_version(REGISTRY),
            lambda: get_account_status(REGISTRY),
            lambda: get_service_status(REGISTRY),
            lambda: get_queue_status(REGISTRY)
        ]

        threads = []
        for func in metrics_functions:
            t = threading.Thread(target=func)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        with cache_lock:
            cached_metrics = prometheus_client.generate_latest(REGISTRY)
            last_update_time = time.time()

        return cached_metrics
    except Exception as e:
        logging.error(f"Error collecting metrics: {str(e)}\n{traceback.format_exc()}")
        return b"Error collecting metrics"


def getcheck():
    global last_update_time, cached_metrics

    current_time = time.time()
    if cached_metrics is None or (current_time - last_update_time) > CACHE_TTL:
        logging.info("Cache expired or empty - collecting fresh metrics")
        return collect_metrics()

    with cache_lock:
        logging.info("Returning cached metrics (last updated %d seconds ago)",
                    (current_time - last_update_time))
        return cached_metrics


# Flask app
app = Flask(__name__)


@app.route("/metrics")
def ApiResponse():
    try:
        metrics = getcheck()
        return Response(metrics, mimetype="text/plain")
    except Exception as e:
        logging.error(f"Error in ApiResponse: {str(e)}\n{traceback.format_exc()}")
        return Response(b"Internal Server Error", status=500)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=PORT_EXPORTER, threaded=True)
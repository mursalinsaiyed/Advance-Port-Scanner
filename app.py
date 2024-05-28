from flask import Flask, render_template, request
import threading
from socket import *
from queue import Queue
import nmap
import subprocess
import os

app = Flask(__name__)

N_THREADS = 200  # Increased number of threads
queue = Queue()
print_lock = threading.Lock()
results = []

# Function to grab the banner from open ports
def grab_banner(conn_skt):
    try:
        conn_skt.send(b'HEAD / HTTP/1.1\r\n\r\n')
        return conn_skt.recv(1024).decode().strip()
    except:
        return 'Banner not available'

# Function to scan a single port
def conScan(tgtHost, tgtPort, detectService):
    try:
        conn_skt = socket(AF_INET, SOCK_STREAM)
        conn_skt.connect((tgtHost, tgtPort))
        conn_skt.settimeout(0.5)  # Reduced timeout
        banner = grab_banner(conn_skt) if detectService else ''
        with print_lock:
            result = f'[+] {tgtPort}/tcp open: {banner}'
            results.append(result)
        conn_skt.close()
    except:
        with print_lock:
            result = f'[-] {tgtPort}/tcp closed'
            results.append(result)

# Worker thread function
def worker(tgtHost, detectService):
    while not queue.empty():
        tgtPort = queue.get()
        conScan(tgtHost, tgtPort, detectService)
        queue.task_done()

# Function to scan multiple ports on a host using multi-threading
def portScan(tgtHost, tgtPorts, detectService):
    global results
    results = []
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        results.append(f'[-] Cannot resolve {tgtHost}')
        return results
    try:
        tgtName = gethostbyaddr(tgtIP)
        results.append(f'\n[+] Scan result of: {tgtName[0]}')
    except:
        results.append(f'\n[+] Scan result of: {tgtIP}')

    setdefaulttimeout(0.5)  # Adjust the timeout value here

    for tgtPort in tgtPorts:
        queue.put(tgtPort)

    for _ in range(N_THREADS):
        thread = threading.Thread(target=worker, args=(tgtHost, detectService))
        thread.daemon = True
        thread.start()

    queue.join()
    return results

# Function to detect operating system using nmap
def detect_os(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments='-O')
        os_results = []
        for host in nm.all_hosts():
            os_results.append(f"Host : {host} ({nm[host].hostname()})")
            os_results.append(f"State : {nm[host].state()}")
            if 'osclass' in nm[host]:
                for osclass in nm[host]['osclass']:
                    os_results.append(f"OS Type : {osclass['type']}")
                    os_results.append(f"OS Vendor : {osclass['vendor']}")
                    os_results.append(f"OS Family : {osclass['osfamily']}")
                    os_results.append(f"OS Generation : {osclass['osgen']}")
                    os_results.append(f"OS Accuracy : {osclass['accuracy']}%")
        return os_results
    except Exception as e:
        return [f"Operating System: OS Detection Failed ({str(e)})"]

# Function to perform traceroute using subprocess
def trace_route(target):
    try:
        result = subprocess.check_output(['tracert', target], universal_newlines=True)
        return result.split('\n')
    except Exception as e:
        return [f"Traceroute: Traceroute Failed ({str(e)})"]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    scan_type = request.form['scanType']
    detect_service = 'detectService' in request.form
    detect_os_flag = 'detectOS' in request.form
    trace_route_flag = 'traceRoute' in request.form

    if scan_type == 'light':
        target_ports = list(range(1, 1025))
    elif scan_type == 'deep':
        target_ports = list(range(1, 65536))

    results = portScan(target, target_ports, detect_service)

    if detect_os_flag:
        os_info = detect_os(target)
        results.append("Operating System Info:")
        results.extend(os_info)

    if trace_route_flag:
        trace_info = trace_route(target)
        results.append("Traceroute Results:")
        results.extend(trace_info)

    return '<br>'.join(results)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

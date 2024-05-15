import os
from flask import Flask, render_template, request
import threading
from socket import *
from queue import Queue
import nmap
import subprocess
import platform

app = Flask(__name__)

N_THREADS = 100
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
        conn_skt.settimeout(1)
        banner = grab_banner(conn_skt) if detectService else ''
        with print_lock:
            result = '[+] %d/tcp open: %s' % (tgtPort, banner)
            results.append(result)
        conn_skt.close()
    except:
        with print_lock:
            result = '[-] %d/tcp closed' % tgtPort
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
        results.append('[-] Cannot resolve %s' % tgtHost)
        return results
    try:
        tgtName = gethostbyaddr(tgtIP)
        results.append('\n[+] Scan result of: %s' % tgtName[0])
    except:
        results.append('\n[+] Scan result of: %s' % tgtIP)

    setdefaulttimeout(1)
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

# Function to trace route to the target
def trace_route(target):
    if platform.system().lower() == 'windows':
        command = ['tracert', target]
    else:
        command = ['traceroute', target]

    try:
        result = subprocess.run(command, capture_output=True, text=True)
        return result.stdout.split('\n')
    except Exception as e:
        return [str(e)]

@app.route('/', methods=['GET'])
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
        results.append(f"Operating System: {os_info}")

    if trace_route_flag:
        trace_info = trace_route(target)
        results.append("\nTraceroute Results:")
        results.extend(trace_info)

    return '\n'.join(results)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

from flask import Flask, render_template, request
import threading
from socket import *
from queue import Queue
from scapy.all import IP, TCP, sr, sr1, ICMP

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

# Enhanced OS detection using scapy
def detect_os(ip):
    os_patterns = [
        {"ttl": 64, "window_size": 5840, "os": "Linux (Kernel 2.4 and 2.6)"},
        {"ttl": 64, "window_size": 65535, "os": "Windows"},
        {"ttl": 128, "window_size": 8192, "os": "Windows"},
        {"ttl": 255, "window_size": 4128, "os": "Cisco Router"}
    ]

    # Checking multiple common ports
    for dport in [80, 443, 22, 25, 53]:
        ans, unans = sr(IP(dst=ip)/TCP(dport=dport, flags="S"), timeout=2, verbose=0)
        for sent, received in ans:
            if received.haslayer(TCP):
                ttl = received.ttl
                window_size = received.window
                for pattern in os_patterns:
                    if ttl == pattern["ttl"] and window_size == pattern["window_size"]:
                        return pattern["os"]
    return "OS Detection Failed"

# Function to perform a traceroute
def trace_route(ip):
    max_hops = 30
    results = []
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=ip, ttl=ttl) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=1)
        if reply is None:
            results.append(f"{ttl}\t*")
            break
        elif reply.type == 0:
            results.append(f"{ttl}\t{reply.src}\tDestination reached")
            break
        else:
            results.append(f"{ttl}\t{reply.src}")
    return results

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
        results.append(f"Operating System: {os_info}")

    if trace_route_flag:
        trace_info = trace_route(target)
        results.append("\nTraceroute Results:")
        results.extend(trace_info)

    return '\n'.join(results)

if __name__ == '__main__':
    app.run(debug=True)

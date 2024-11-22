import threading
import time
from web_server import WebServer
from load_balancer import LoadBalancer
from ddos_detector import DDoSDetector
from traffic_monitor import TrafficMonitor
from client import Client

LOG_FILE = "simulation_log.txt"

def log_event(message: str):
    # Simple logger: timestamp + message
    log_entry = f"[{time.strftime('%H:%M:%S')}] {message}"
    print(log_entry)
    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry + "\n")

def simulate_ddos(duration: int, normal_clients: list, attackers: list, failed_detection: bool = False) -> None:
    server1 = WebServer("Server 1", initial_capacity=10, max_capacity=50)
    server2 = WebServer("Server 2", initial_capacity=15, max_capacity=60)
    load_balancer = LoadBalancer([server1, server2])
    ddos_detector = DDoSDetector(load_balancer)
    monitor = TrafficMonitor()

    if failed_detection:
        ddos_detector.attack_threshold = 5000  # unreallistically high to simulate detection failure

    stop_event = threading.Event()
    request_count = {"total": 0, "processed": 0, "blocked": 0}
    blacklist = set()

    def run_client(client: Client):
        while not stop_event.is_set():
            for request in client.send_requests(10):
                if stop_event.is_set():
                    break
                response = load_balancer.distribute_request(request)
                ddos_detector.add_request(request)
                request_count["total"] += 1
                if "blocked" in response:
                    request_count["blocked"] += 1
                    blacklist.add(request.client_ip)
                else:
                    request_count["processed"] += 1
                log_event(f"{request.id} from {request.client_ip}: {response}")

    threads = []
    for client in normal_clients + attackers:
        thread = threading.Thread(target=run_client, args=(client,))
        thread.daemon = True
        threads.append(thread)
        thread.start()

    start = time.time()
    try:
        while time.time() - start < duration:
            traffic_rate = sum(server.current_load for server in [server1, server2])
            if monitor.detect_anomaly(traffic_rate):
                log_event("Traffic anomaly detected. Mitigating...")
                ddos_detector.mitigate_attack()
            elif ddos_detector.detect_attack():
                log_event("DDoS attack detected. Mitigating...")
                ddos_detector.mitigate_attack()
            else:
                ddos_detector.normal_operation()

            for server in [server1, server2]:
                server.process_queue()
            time.sleep(0.1)
    finally:
        stop_event.set()
        time.sleep(0.5)

    summary = "\n=== Simulation Summary ===\n"
    summary += f"Total Requests: {request_count['total']}\n"
    summary += f"Processed Requests: {request_count['processed']}\n"
    summary += f"Blocked Requests: {request_count['blocked']}\n"
    summary += f"Blacklisted IPs: {len(blacklist)}\n"
    for ip in blacklist:
        summary += f"  Blacklisted IP: {ip}\n"
    for server in [server1, server2]:
        summary += f"{server.name}:\n"
        summary += f"  Processed Requests: {server.processed_requests}\n"
        summary += f"  Average Response Time: {server.avg_response_time():.4f} seconds\n"
        summary += f"  Throughput: {server.throughput():.2f} Bytes/s\n"
    summary += "=== End of Summary ===\n"

    log_event(summary)
    print(summary)

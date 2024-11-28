import threading
import time
import random
from web_server import WebServer
from client import Client
from load_balancer import LoadBalancer
from ddos_detector import DDoSDetector
from custom_logging import log_event
from traffic_monitor import TrafficMonitor

COLORS = {
    "RESET": "\033[0m",
    "INFO": "\033[94m",
    "WARNING": "\033[93m",
    "ERROR": "\033[91m",
    "SUCCESS": "\033[92m"
}


class TrafficSimulator:
    def __init__(self, server_host="127.0.0.1", server_port=8080, num_servers=2):
        self.server_host = server_host
        self.server_port = server_port
        self.servers = [WebServer(host=server_host, port=server_port + i) for i in range(num_servers)]
        self.balancer = LoadBalancer(self.servers)
        self.detector = DDoSDetector(self.balancer, window_size=15, burst_threshold=20, sustained_threshold=10)
        self.monitor = TrafficMonitor(self.balancer, self.detector)
        self.client = Client(server_host, server_port)
        self.blacklist = set()

    def start_servers(self):
        for server in self.servers:
            threading.Thread(target=server.start, daemon=True).start()

        monitor_thread = threading.Thread(target=self.monitor.monitor_traffic, daemon=True)
        monitor_thread.start()

        log_event("INFO", "Simulation", f"System started with {len(self.servers)} servers.")
        time.sleep(2)  # Allow servers to initialize

    def stop_servers(self):
        for server in self.servers:
            server.stop()

        log_event("INFO", "Simulation", "All servers stopped.")

    def update_blacklist(self):
        self.blacklist = self.balancer.blacklist.copy()

    def normal_traffic(self, request_count=20, delay_range=(1, 2)):
        log_event("INFO", "Simulation", "Starting normal traffic simulation.")
        for _ in range(request_count):
            ip = f"192.168.1.{random.randint(1, 255)}"
            self.detector.record_request(ip)
            self.monitor.record_request()
            delay = random.uniform(*delay_range)
            self.client.send_request(delay=delay)

    def ddos_traffic(self, request_count=800, delay_range=(0.01, 0.02), attacker_ip_range=(1, 50)):
        log_event("WARNING", "Simulation", "Starting DDoS traffic simulation.")
        threads = []
        for _ in range(request_count):
            ip = f"192.168.1.{random.randint(*attacker_ip_range)}"
            self.detector.record_request(ip)
            self.monitor.record_request()
            thread = threading.Thread(target=self.client.send_request, args=(delay_range[0],), daemon=True)
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()

        self.update_blacklist()
        if self.blacklist:
            print(f"{COLORS['ERROR']}DDoS Detected: Blocked IPs - {', '.join(self.blacklist)}{COLORS['RESET']}")
        else:
            print(f"{COLORS['INFO']}No IPs were blocked during DDoS simulation.{COLORS['RESET']}")

    def mixed_traffic(self, total_requests=300, ddos_ratio=0.3, delay_range_normal=(1, 2), delay_range_ddos=(0.01, 0.05)):
        # total_requests: Total number of requests (normal + DDoS)
        # ddos_ratio: Proportion of DDoS requests (for example 0.3 for 30% DDoS traffic)
        # delay_range_normal: Delay range for normal traffic
        # delay_range_ddos: Delay range for DDoS traffic
        log_event("INFO", "Simulation", "Starting mixed traffic simulation.")
        threads = []

        # Calculate number of normal and DDoS requests
        ddos_requests = int(total_requests * ddos_ratio)
        normal_requests = total_requests - ddos_requests

        for _ in range(total_requests):
            # Alternate between normal and DDoS requests
            if ddos_requests > 0 and (random.random() < ddos_ratio):
                ip = f"192.168.1.{random.randint(1, 50)}"
                delay = random.uniform(*delay_range_ddos)
                ddos_requests -= 1
            else:
                ip = f"192.168.1.{random.randint(100, 255)}"
                delay = random.uniform(*delay_range_normal)
                normal_requests -= 1

            self.monitor.record_request()
            self.detector.record_request(ip)
            thread = threading.Thread(target=self.client.send_request, args=(delay,), daemon=True)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        self.update_blacklist()
        log_event("INFO", "Simulation", f"Mixed traffic simulation completed. {len(self.blacklist)} IPs were blocked.")

    
    def failed_detection(self, traffic_count=300, burst_size=19, burst_delay=0.4, reset_time=10):
        log_event("WARNING", "Simulation", "Starting failed detection simulation.")
        threads = []
        ip_range = (200, 250)

        for _ in range(traffic_count // burst_size):
            burst_ips = [f"192.168.1.{random.randint(*ip_range)}" for _ in range(burst_size)]

            for ip in burst_ips:
                self.detector.record_request(ip)
                self.monitor.record_request()
                thread = threading.Thread(target=self.client.send_request, args=(burst_delay,), daemon=True)
                threads.append(thread)
                thread.start()

            time.sleep(reset_time)

        for thread in threads:
            thread.join()

        self.update_blacklist()
        if self.blacklist:
            print(f"{COLORS['WARNING']}Unexpected Blocked IPs: {', '.join(self.blacklist)}{COLORS['RESET']}")
        else:
            print(f"{COLORS['SUCCESS']}Failed to Detect simulation succeeded. No IPs were blocked.{COLORS['RESET']}")


    def print_summary(self, traffic_type):
        print(f"{COLORS['INFO']}Simulation Summary: {traffic_type}{COLORS['RESET']}")
        print(f"{COLORS['SUCCESS']}Blocked IPs: {', '.join(self.blacklist) if self.blacklist else 'None'}{COLORS['RESET']}")
        print(f"{COLORS['INFO']}End of {traffic_type} simulation.{COLORS['RESET']}\n")


def main():
    simulator = TrafficSimulator()
    simulator.start_servers()
    try:

        simulator.normal_traffic()
        simulator.print_summary("Normal Traffic")

        simulator.ddos_traffic()
        simulator.print_summary("DDoS Traffic")

        simulator.mixed_traffic()
        simulator.print_summary("Mixed Traffic")

        simulator.failed_detection()
        simulator.print_summary("Failed Detection Traffic")

    finally:

        simulator.stop_servers()


if __name__ == "__main__":
    main()

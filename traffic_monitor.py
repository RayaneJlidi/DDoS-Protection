import time
from collections import deque
from custom_logging import log_event
from ddos_detector import DDoSDetector
from load_balancer import LoadBalancer


class TrafficMonitor:
    def __init__(self, balancer: LoadBalancer, detector: DDoSDetector, sampling_interval: int = 5):
        self.balancer = balancer
        self.detector = detector
        self.sampling_interval = sampling_interval
        self.total_requests = 0
        self.request_timestamps = deque()
        self.traffic_rate_history = deque(maxlen=10) 

    def record_request(self):
        self.total_requests += 1
        self.request_timestamps.append(time.time())

    def calculate_traffic_rate(self):
        current_time = time.time()

        # Outdated timestamps are removed
        while self.request_timestamps and current_time - self.request_timestamps[0] > self.sampling_interval:
            self.request_timestamps.popleft()

        rate = len(self.request_timestamps) / self.sampling_interval
        self.traffic_rate_history.append(rate)
        return rate

    def monitor_traffic(self):
        while True:
            time.sleep(self.sampling_interval)

            traffic_rate = self.calculate_traffic_rate()
            log_event("INFO", "TrafficMonitor", f"Traffic rate: {traffic_rate:.2f} requests/sec")
            self.detect_anomalies(traffic_rate)
            self.log_loads()

    def detect_anomalies(self, traffic_rate: float):
        if len(self.traffic_rate_history) > 1:
            avg_rate = sum(self.traffic_rate_history) / len(self.traffic_rate_history)

            if traffic_rate > 1.5 * avg_rate:
                log_event("WARNING", "TrafficMonitor", f"Anomaly detected: Traffic spike to {traffic_rate:.2f} requests/sec")
                self.adjust_threshold(avg_rate)

    def adjust_threshold(self, avg_rate: float):
        burst_threshold = max(20, int(avg_rate * 2))
        sustained_threshold = max(10, int(avg_rate * 1.5))

        self.detector.burst_threshold = burst_threshold
        self.detector.sustained_threshold = sustained_threshold
        log_event("INFO", "TrafficMonitor", f"Adjusted thresholds: Burst={burst_threshold}, Sustained={sustained_threshold}")

    def log_loads(self):
        server_loads = [(server.port, server.load()) for server in self.balancer.servers]
        log_event("INFO", "TrafficMonitor", f"Server loads: {server_loads}")

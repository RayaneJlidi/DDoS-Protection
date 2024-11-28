from collections import defaultdict, deque
from typing import DefaultDict, Deque
import time
from load_balancer import LoadBalancer
from custom_logging import log_event

# Initialize the DDoS Detector with thresholds and mitigation strategies.
class DDoSDetector:
    def __init__(self, balancer: LoadBalancer, window_size: int = 10, burst_threshold: int = 20, sustained_threshold: int = 10) -> None:
        """
        balancer: The load balancer instance to manage traffic control.
        window_size: Monitoring window in seconds for request analysis.
        burst_threshold: Number of requests in the window to trigger a burst alert.
        sustained_threshold: Requests/sec rate to trigger sustained anomaly alerts.
        """
        self.balancer = balancer
        self.window_size = window_size
        self.burst_threshold = burst_threshold
        self.sustained_threshold = sustained_threshold

        self.request_history: Deque[tuple] = deque()  # Stores (IP, timestamp)
        self.ip_request_count: DefaultDict[str, int] = defaultdict(int)
        self.ip_request_window: DefaultDict[str, Deque[float]] = defaultdict(deque)
        self.ip_scores: DefaultDict[str, int] = defaultdict(int)  # Tracks how malicious an IP is

        # Manage mitigation
        self.blacklist_time: DefaultDict[str, float] = defaultdict(float)
        self.throttled_ips: set = set()

    # Record an incoming request and evaluate the client's behavior
    def record_request(self, client_ip: str) -> None:
        current_time = time.time()

        # Add the new request to the tracking systems
        self.request_history.append((client_ip, current_time))
        self.ip_request_count[client_ip] += 1
        self.ip_request_window[client_ip].append(current_time)

        self.clean(current_time)
        self.analyze_ip(client_ip)

    # Analyze a specific IP for unusual or malicious behavior
    def analyze_ip(self, client_ip: str) -> None:

        request_window = self.ip_request_window[client_ip]
        request_rate = len(request_window) / self.window_size

        # Detect burst activity
        if len(request_window) > self.burst_threshold:
            log_event("WARNING", "DDoSDetector", f"High burst activity detected for IP: {client_ip}.")
            self.handle_mal_ip(client_ip, reason="burst activity")

        # Detect sustained high traffic
        elif request_rate > self.sustained_threshold:
            log_event("WARNING", "DDoSDetector", f"Sustained high traffic detected for IP: {client_ip}.")
            self.handle_mal_ip(client_ip, reason="sustained traffic")

    # Apply mitigation for a malicious IP
    def handle_mal_ip(self, client_ip: str, reason: str) -> None:
        self.ip_scores[client_ip] += 1
        score = self.ip_scores[client_ip]

        if score >= 3:  # High severity: Blacklist IP
            if client_ip not in self.balancer.blacklist:
                self.balancer.blacklist_ip(client_ip)
                self.blacklist_time[client_ip] = time.time()
                log_event("ERROR", "DDoSDetector", f"Blacklisted IP: {client_ip} (Reason: {reason}, Score: {score})")

        elif score == 2:  # Moderate severity: Throttle IP
            self.throttled_ips.add(client_ip)
            log_event("WARNING", "DDoSDetector", f"Throttling IP: {client_ip} (Reason: {reason}, Score: {score})")

        else:  # Low severity: Issue a challenge (Something like CAPTCHA)
            log_event("INFO", "DDoSDetector", f"Issuing challenge to IP: {client_ip} (Reason: {reason}, Score: {score})")

    # Remove outdated request data
    def clean(self, current_time: float) -> None:

        # Clean up old requests outside the monitoring window
        while self.request_history and current_time - self.request_history[0][1] > self.window_size:
            ip, _ = self.request_history.popleft()
            self.ip_request_count[ip] -= 1
            if self.ip_request_count[ip] <= 0:
                del self.ip_request_count[ip]

        # Clean up per-IP request windows
        for ip, timestamps in self.ip_request_window.items():
            self.ip_request_window[ip] = deque(t for t in timestamps if current_time - t <= self.window_size)

        # Remove IPs from throttling after cooldown
        for ip in list(self.throttled_ips):
            if current_time - self.blacklist_time[ip] > self.window_size:
                self.throttled_ips.remove(ip)
                log_event("INFO", "DDoSDetector", f"Throttling lifted for IP: {ip}.")

        # Remove IPs from the blacklist after a longer cooldown
        for ip in list(self.balancer.blacklist):
            if current_time - self.blacklist_time[ip] > self.window_size * 3:
                self.balancer.whitelist(ip)
                log_event("INFO", "DDoSDetector", f"IP removed from blacklist: {ip} after cooldown.")

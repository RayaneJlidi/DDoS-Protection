import time
from collections import deque, defaultdict
from typing import Deque
from load_balancer import LoadBalancer
from web_server import Request

class DDoSDetector:
    """Detects and mitigates potential DDoS attacks."""
    def __init__(self, load_balancer: LoadBalancer):
        self.load_balancer = load_balancer
        self.request_history: Deque[Request] = deque(maxlen=60)  # Track last 60 seconds of requests
        self.ip_counts: DefaultDict[str, int] = defaultdict(int) # Track requests per IP
        self.threshold = 200  # Max allowed requests per minute

    def add_request(self, request: Request) -> None:
        # Log a request
        self.request_history.append(request)
        self.ip_counts[request.client_ip] += 1

    def detect_attack(self) -> bool:
         # Check for DDoS patterns
        recent_requests = len([r for r in self.request_history if time.time() - r.timestamp < 60])
        if recent_requests > self.threshold:
            return True

        # Check for individual IP abuse
        for ip, count in self.ip_counts.items():
            if count > self.threshold / 10:  # 10% of traffic from one IP
                return True

        return False

    def mitigate_attack(self) -> None:
        print("Mitigating attack: Reducing thresholds and increasing server capacity.")
        self.load_balancer.update_threshold(5)  # Tighten rate limit
        for server in self.load_balancer.servers:
            server.capacity = min(server.max_capacity, server.capacity * 2)  # Dobule capacity

    def normal_operation(self) -> None:
        print("Resuming normal operations.")
        self.load_balancer.update_threshold(10)  # Restore rate limit
        for server in self.load_balancer.servers:
            server.capacity = max(server.initial_capacity, server.capacity // 2)  # Reset capacity

import random
from collections import defaultdict
from typing import List, DefaultDict, Set
from web_server import WebServer, Request

class LoadBalancer:
    """Manages traffic distribution and implements rate limiting."""
    def __init__(self, servers: List[WebServer]):
        self.servers = servers
        self.request_counts: DefaultDict[str, int] = defaultdict(int)
        self.blacklist: Set[str] = set()
        self.threshold = 5  # Requests per IP per minute

    def distribute_request(self, request: Request) -> str:
        """Handle an incoming request: block, queue, or distribute to a server."""
        if request.client_ip in self.blacklist:
            return "Request blocked: IP blacklisted"

        # Count requests from each IP
        self.request_counts[request.client_ip] += 1
        if self.request_counts[request.client_ip] > self.threshold:
            self.blacklist.add(request.client_ip)
            return "Request blocked: Rate limit exceeded"

        server = self.select_server()
        return server.handle_request(request)

    def select_server(self) -> WebServer:
        """Select a server using weighted random distribution."""
        weights = [server.capacity - server.current_load for server in self.servers]
        total_weight = sum(weights)
        weights = [w / total_weight for w in weights] if total_weight else [1 / len(self.servers)] * len(self.servers)
        return random.choices(self.servers, weights=weights, k=1)[0]

    def update_threshold(self, new_threshold: int) -> None:
        """Update rate-limiting threshold."""
        self.threshold = new_threshold

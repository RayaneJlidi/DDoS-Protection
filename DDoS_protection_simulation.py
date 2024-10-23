import random
import time
from collections import deque, defaultdict
import threading
import ipaddress
from typing import List, Deque, DefaultDict, Set

class Request:
    """Represents a single request in the system."""
    def __init__(self, id: str, client_ip: str, timestamp: float, size: int):
        self.id = id
        self.client_ip = client_ip
        self.timestamp = timestamp
        self.size = size  # Request size in bytes

class WebServer:
    """Simulates a web server with dynamic capacity and request handling"""
    def __init__(self, name: str, initial_capacity: int, max_capacity: int):
        self.name = name
        self.initial_capacity = initial_capacity
        self.max_capacity = max_capacity
        self.capacity = initial_capacity
        self.current_load = 0
        self.queue: Deque[Request] = deque()
        self.processed_requests = 0
        self.total_response_time = 0.0
        self.total_bytes_processed = 0

    def handle_request(self, request: Request) -> str:
        """Process a request or add it to the queue if at capacity"""
        if self.current_load < self.capacity:
            self.current_load += 1
            # Adjusted processing time to ensure reasonable delays
            processing_time = max(0.05, (request.size / 1000) * (1 + (self.current_load / self.capacity)))
            time.sleep(processing_time)
            self.current_load -= 1
            self.processed_requests += 1
            self.total_response_time += processing_time
            self.total_bytes_processed += request.size
            return f"Request {request.id} processed by {self.name}"
        else:
            self.queue.append(request)
            return f"Request {request.id} queued in {self.name}"

    def process_queue(self) -> None:
        """Process requests in the queue if server has available capacity"""
        while self.queue and self.current_load < self.capacity:
            request = self.queue.popleft()
            self.handle_request(request)

    def get_average_response_time(self) -> float:
        """Calculate the average response time for all processed requests"""
        if self.processed_requests == 0:
            return 0
        return self.total_response_time / self.processed_requests

    def get_throughput(self) -> float:
        """Calculate the server's throughput in Bytes/s"""
        if self.total_response_time == 0:
            return 0
        return self.total_bytes_processed / self.total_response_time

class LoadBalancer:
    """Distributes incoming requests across multiple servers using weighted random distribution"""
    def __init__(self, servers: List[WebServer]):
        self.servers = servers
        self.request_counts: DefaultDict[str, int] = defaultdict(int)
        self.blacklist: Set[str] = set()
        self.threshold = 6

    def get_server_weights(self) -> List[float]:
        """Calculate weights for each server based on available capacity"""
        weights = []
        for server in self.servers:
            available_capacity = server.capacity - server.current_load
            # Small constant to avoid zero weights
            weight = max(0.1, available_capacity / server.capacity)
            weights.append(weight)
        return weights

    def select_server(self) -> WebServer:
        """Select a server using weighted random distribution"""
        weights = self.get_server_weights()
        
        # Normalize weights to sum to 1.0
        total_weight = sum(weights)
        if total_weight == 0:
            # Fallback to equal weights if all servers are at capacity
            weights = [1/len(self.servers)] * len(self.servers)
        else:
            weights = [w/total_weight for w in weights]
            
        return random.choices(self.servers, weights=weights, k=1)[0]

    def distribute_request(self, request: Request) -> str:
        """Handle an incoming request: block, queue, or distribute to a server"""
        if request.client_ip in self.blacklist:
            return "Request blocked: IP blacklisted"

        self.request_counts[request.client_ip] += 1
        if self.request_counts[request.client_ip] > self.threshold:
            self.blacklist.add(request.client_ip)
            return "Request blocked: Rate limit exceeded"

        # Select server using weighted random distribution
        server = self.select_server()
        return server.handle_request(request)

    def update_threshold(self, new_threshold: int) -> None:
        """Update the rate limiting threshold"""
        self.threshold = new_threshold

class DDoSDetector:
    """Monitors traffic patterns to detect potential DDoS attacks"""
    def __init__(self, load_balancer: LoadBalancer):
        self.load_balancer = load_balancer
        self.request_history: Deque[Request] = deque(maxlen=60)  # Store last one minute of requests
        self.ip_request_counts: DefaultDict[str, int] = defaultdict(int)
        self.attack_threshold = 6  # Lower threshold to detect attacks quickly

    def add_request(self, request: Request) -> None:
        """Record a new request for attack detection purposes"""
        self.request_history.append(request)
        self.ip_request_counts[request.client_ip] += 1

    def detect_attack(self) -> bool:
        """Determine if the current traffic pattern indicates a DDoS attack"""
        if len(self.request_history) < 30:
            return False

        # Check overall request rate
        recent_requests = len([r for r in self.request_history if time.time() - r.timestamp < 60])
        if recent_requests > self.attack_threshold:
            return True

        # Check for suspicious patterns from individual IPs
        for ip, count in self.ip_request_counts.items():
            if count > self.attack_threshold / 5:  # If any IP accounts for more than 20% of threshold
                return True

        return False

    def mitigate_attack(self) -> None:
        """Implement mitigation strategies when an attack is detected"""
        self.load_balancer.update_threshold(5)  # Reduce threshold during attack
        for server in self.load_balancer.servers:
            server.capacity = min(server.max_capacity, server.capacity * 2)  # Increase capacity, max at max_capacity

    def normal_operation(self) -> None:
        """Reset system parameters to normal when no attack is detected"""
        self.load_balancer.update_threshold(5)  # Reset threshold
        for server in self.load_balancer.servers:
            server.capacity = max(server.initial_capacity, server.capacity // 2)  # Decrease capacity, min at initial

class Client:
    """Simulates a client sending requests to the system"""
    def __init__(self, name: str, request_rate: float, is_attacker: bool = False):
        self.name = name
        self.request_rate = request_rate
        self.is_attacker = is_attacker

    def generate_requests(self, num_requests: int):
        """Generate a specified number of requests"""
        for i in range(num_requests):
            if self.is_attacker:
                ip = str(ipaddress.IPv4Address(random.randint(2**30, 2**30 + 10)))
            else:
                ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
            
            # Generate request size - larger for attackers
            size = random.randint(1000, 5000) if not self.is_attacker else random.randint(5000, 10000)
            
            yield Request(f"{self.name}-{i+1}", ip, time.time(), size)
            time.sleep(1 / self.request_rate)

def simulate_ddos_protection(duration: int, normal_clients: List[Client], attackers: List[Client]) -> None:
    """
    Run a simulation of the DDoS protection system.
    
    Args:
    duration: The duration of the simulation in seconds.
    normal_clients: A list of normal client objects.
    attackers: A list of attacker client objects.
    """
    server1 = WebServer("Server 1", initial_capacity=10, max_capacity=50)
    server2 = WebServer("Server 2", initial_capacity=15, max_capacity=60)
    load_balancer = LoadBalancer([server1, server2])
    ddos_detector = DDoSDetector(load_balancer)

    # Shared flag to signal the end of the simulation
    simulation_end = threading.Event()

    def run_client(client: Client) -> None:
        """Simulate a client's behavior over time."""
        while not simulation_end.is_set():
            for request in client.generate_requests(10):  # Increased number of requests generated
                if simulation_end.is_set():
                    break
                response = load_balancer.distribute_request(request)
                ddos_detector.add_request(request)
                print(f"{request.id} from {request.client_ip}: {response}")

    # Start client threads
    threads = []
    for client in normal_clients + attackers:
        thread = threading.Thread(target=run_client, args=(client,))
        thread.daemon = True  # Set as daemon so they don't prevent program exit
        threads.append(thread)
        thread.start()

    # Main simulation loop
    start_time = time.time()
    attack_detected = False
    try:
        while time.time() - start_time < duration:
            if ddos_detector.detect_attack():
                if not attack_detected:
                    print("DDoS attack detected! Implementing mitigation strategies...")
                    attack_detected = True
                ddos_detector.mitigate_attack()
            else:
                if attack_detected:
                    print("Attack mitigated. Returning to normal operation.")
                    attack_detected = False
                ddos_detector.normal_operation()

            for server in [server1, server2]:
                server.process_queue()

            time.sleep(0.1)
    finally:
        # Signal all threads to stop
        simulation_end.set()

        # Wait a short time for threads to finish
        time.sleep(0.5)

    # Print simulation results
    print("\nSimulation Results:")
    for server in [server1, server2]:
        print(f"{server.name}:")
        print(f"  Processed Requests: {server.processed_requests}")
        print(f"  Average Response Time: {server.get_average_response_time():.4f} seconds")
        print(f"  Throughput: {server.get_throughput():.2f} Bytes/s")
    print(f"Blacklisted IPs: {len(load_balancer.blacklist)}")

# Run the simulation
normal_clients = [Client(f"Normal Client {i}", request_rate=3) for i in range(2)]
attackers = [Client(f"Attacker {i}", request_rate=75, is_attacker=True) for i in range(5)] 
simulate_ddos_protection(duration=60, normal_clients=normal_clients, attackers=attackers)

import random
import time
from web_server import Request

class Client:
    # Represents a client that sends requests to the system
    def __init__(self, client_name, request_rate, attacker_flag=False):
        self.client_name = client_name
        self.request_rate = request_rate  # How frequently requests are sent (per second)
        self.attacker_flag = attacker_flag  # Is this client an attacker? (For logging purposes, this doesn't affect the algorithm)

    def send_requests(self, total_requests):
        """
        Generates and sends a specified number of requests.
        Attacker clients have specific IP ranges and larger request sizes.
        """
        for idx in range(total_requests):
            if self.attacker_flag:
                # Attackers use smaller IP ranges
                ip_address = f"192.168.1.{random.randint(1, 20)}"
                req_size = random.randint(5000, 9000)  # Larger size for attackers
            else:
                # Regular clients have a bigger IP distribution
                ip_address = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
                req_size = random.randint(1000, 4000)  # Smaller size for normal traffic

            req = Request(
                id=f"{self.client_name}-{idx+1}",
                client_ip=ip_address,
                timestamp=time.time(),  # Capture current time for each request
                size=req_size,
            )

            print(f"Request {req.id} sent from {ip_address} (size: {req_size})")
            time.sleep(1 / self.request_rate)  # delay based on request rate

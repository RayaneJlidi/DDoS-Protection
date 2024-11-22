import time
from collections import deque
from typing import Deque

class Request:
    # represents a network request
    def __init__(self, id: str, client_ip: str, timestamp: float, size: int):
        self.id = id
        self.client_ip = client_ip
        self.timestamp = timestamp
        self.size = size

class WebServer:
    # simulates a web server
    def __init__(self, name: str, initial_capacity: int, max_capacity: int):
        self.name = name
        self.initial_capacity = initial_capacity
        self.max_capacity = max_capacity
        self.capacity = initial_capacity
        self.current_load = 0
        self.queue: Deque[Request] = deque()
        self.processed_requests = 0
        self.response_time = 0.0
        self.processed_bytes = 0

    def handle_request(self, request: Request) -> str:
        # Try to process the request; if full, put in the queu
        if self.current_load < self.capacity:
            self.current_load += 1
            processing_time = max(0.05, (request.size / 1000) * (1 + (self.current_load / self.capacity)))
            # simulate work being done
            time.sleep(processing_time)
            self.current_load -= 1
            self.processed_requests += 1
            self.response_time += processing_time
            self.processed_bytes += request.size
            return f"Request {request.id} processed by {self.name}"
        else:
            self.queue.append(request)
            return f"Request {request.id} queued in {self.name}"

    def process_queue(self) -> None:
        # Handle requests in the queue if there's room for them
        while self.queue and self.current_load < self.capacity:
            request = self.queue.popleft()
            self.handle_request(request)

    def avg_response_time(self) -> float:
        if self.processed_requests == 0:
            return 0
        
        return self.response_time / self.processed_requests

    def throughput(self) -> float:
        if self.response_time == 0:
            return 0
        
        return self.processed_bytes / self.response_time

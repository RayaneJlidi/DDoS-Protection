from typing import List, DefaultDict, Set
from web_server import WebServer
from custom_logging import log_event
import threading
import time


class LoadBalancer:
    def __init__(self, servers: List[WebServer], throttle_delay: float = 1.0):
        self.servers = servers
        self.blacklist: Set[str] = set()
        self.throttled_ips: Set[str] = set()
        self.req_count: DefaultDict[str, int] = DefaultDict(int)  # Tracks request counts per IP
        self.lock = threading.Lock()
        self.throttle_delay = throttle_delay

    # Process request, apply mitigation strategies and routing it to a server
    def process_request(self, client_socket, client_address):
        client_ip = client_address[0]
        with self.lock:
            # Check if IP is blacklisted
            if client_ip in self.blacklist:
                log_event("WARNING", "LoadBalancer", f"Blocked request from blacklisted IP: {client_ip}")
                client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nAccess Denied")
                client_socket.close()
                return

            # Enforce throttling
            if client_ip in self.throttled_ips:
                log_event("INFO", "LoadBalancer", f"Throttling request from IP: {client_ip}")
                time.sleep(self.throttle_delay)

            # Challenge for flagged IPs (something like CAPTCHA)
            if client_ip not in self.blacklist and client_ip in self.req_count:
                if self.req_count[client_ip] > 10:
                    log_event("INFO", "LoadBalancer", f"Issuing challenge to IP: {client_ip}")
                    client_socket.sendall(b"HTTP/1.1 429 Too Many Requests\r\n\r\nPlease verify yourself")
                    client_socket.close()
                    return

        server = self.select_server()
        if server:
            server_thread = threading.Thread(target=server.process_request, args=(client_socket, client_address))
            server_thread.start()
        else:
            log_event("ERROR", "LoadBalancer", f"No servers available to handle request from IP: {client_ip}")
            client_socket.sendall(b"HTTP/1.1 503 Service Unavailable\r\n\r\nServer Overloaded")
            client_socket.close()

    # Select the least-loaded server to handle the request
    def select_server(self) -> WebServer:
        with self.lock:
            available_servers = [(server, server.load()) for server in self.servers]
            available_servers = [server for server, load in available_servers if load < server.max_connections]

            if not available_servers:
                return None

            # Get the least-loaded server
            return sorted(available_servers, key=lambda s: s.load())[0]

    # Blacklists a given IP address
    def blacklist_ip(self, ip: str):
        with self.lock:
            self.blacklist.add(ip)
            log_event("WARNING", "LoadBalancer", f"Blacklisted IP: {ip}")

    def whitelist(self, ip: str):
        with self.lock:
            if ip in self.blacklist:
                self.blacklist.remove(ip)
                log_event("INFO", "LoadBalancer", f"Removed IP: {ip} from blacklist")

    def throttle_ip(self, ip: str):
        with self.lock:
            self.throttled_ips.add(ip)
            log_event("INFO", "LoadBalancer", f"Throttling IP: {ip}")

    def remove_from_throttle(self, ip: str):
        with self.lock:
            if ip in self.throttled_ips:
                self.throttled_ips.remove(ip)
                log_event("INFO", "LoadBalancer", f"Removed IP: {ip} from throttling")

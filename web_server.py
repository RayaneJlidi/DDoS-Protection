import socket
import threading
import time
from custom_logging import log_event


class WebServer:
    def __init__(self, host="127.0.0.1", port=8080, max_connections=100):
        self.host = host
        self.port = port
        self.max_connections = max_connections
        self.active_connections = 0
        self.lock = threading.Lock()
        self.running = False

    def load(self):
        return self.active_connections

    def process_request(self, client_socket, client_address):
        with self.lock:
            self.active_connections += 1

        log_event("INFO", "Request Received", f"IP: {client_address[0]} | Port: {client_address[1]}")

        # Simulate server processing
        time.sleep(2)

        client_socket.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, World!")
        client_socket.close()

        with self.lock:
            self.active_connections -= 1

        log_event("INFO", "Request Processed", f"IP: {client_address[0]} | Active Connections: {self.active_connections}")

    def start(self):
        self.running = True
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(self.max_connections)
        log_event("INFO", "Server Started", f"Listening on {self.host}:{self.port}")

        while self.running:
            try:
                client_socket, client_address = server_socket.accept()
                with self.lock:
                    if self.active_connections >= self.max_connections:
                        log_event("WARNING", "Connection Rejected", f"IP: {client_address[0]} | Too Many Connections")
                        client_socket.sendall(b"HTTP/1.1 503 Service Unavailable\r\n\r\nServer Overloaded")
                        client_socket.close()
                        continue

                threading.Thread(target=self.process_request, args=(client_socket, client_address), daemon=True).start()

            except socket.error as e:
                log_event("ERROR", "Socket Error", str(e))
                break

        server_socket.close()

    def stop(self):
        self.running = False
        log_event("INFO", "Server Stopped", f"Server on {self.host}:{self.port} stopped.")

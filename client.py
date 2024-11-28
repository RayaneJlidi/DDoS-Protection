import socket
import time
from custom_logging import log_event


class Client:
    def __init__(self, server_host: str = "127.0.0.1", server_port: int = 8080) -> None:
        self.server_host = server_host
        self.server_port = server_port

    # Sends a single request to the server, then waits for the specified delay
    def send_request(self, delay: float = 1.0) -> None:
        try:
            # Set up and connect the socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.server_host, self.server_port))

            # Send a basic HTTP GET request
            client_socket.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")

            response = client_socket.recv(1024)
            log_event("INFO", "Response Received", response.decode('utf-8').strip())

        except socket.error as e:
            log_event("ERROR", "Socket Error", str(e))

        finally:
            client_socket.close()

        # Delay to control request frequency
        time.sleep(delay)

import asyncio
import time
import psutil
from typing import Dict
from collections import deque
import statistics
from datetime import datetime
from custom_logging import log_event

class WebServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080, max_connections: int = 100):
        self.host = host
        self.port = port
        self.max_connections = max_connections
        
        self.active_connections = 0
        self.total_requests = 0
        self.error_count = 0
        self.start_time = time.time()
        self.running = False
        
        self._metrics_lock = asyncio.Lock()
        self.response_times = deque(maxlen=100)
        self.request_times = deque(maxlen=100)
        self.errors_per_min = deque(maxlen=60)
        
        self.process = psutil.Process()
        
        self.last_min = int(time.time() / 60)
        self.current_minute_errors = 0

    async def get_load(self) -> float:
        try:
            cpu_percent = await asyncio.to_thread(self.process.cpu_percent)
            memory_percent = await asyncio.to_thread(self.process.memory_percent)
            connection_load = (self.active_connections / self.max_connections) * 100
            return max(cpu_percent, memory_percent, connection_load)
        except Exception as e:
            log_event("ERROR", f"Server {self.port}", f"Error getting load: {str(e)}")
            return 0.0

    async def handle_request(self) -> str:
        start_time = time.time()
        
        if not self.running:
            raise Exception("Server is not running")

        # Track request
        async with self._metrics_lock:
            self.total_requests += 1
            self.request_times.append(start_time)
            current_connections = self.active_connections

        # Check capacity
        if current_connections >= self.max_connections:
            raise Exception("Server at maximum capacity")

        try:
            async with self._metrics_lock:
                self.active_connections += 1

            # Simulate processing
            await asyncio.sleep(0.1)
            response = self._gen_response()
            
            response_time = time.time() - start_time
            async with self._metrics_lock:
                self.response_times.append(response_time)
            
            return response

        except Exception as e:
            async with self._metrics_lock:
                self.error_count += 1
                await self._track_error()
            log_event("ERROR", f"Server {self.port}", str(e))
            raise
        finally:
            async with self._metrics_lock:
                self.active_connections = max(0, self.active_connections - 1)

    async def _track_error(self):
        current = int(time.time() / 60)
        if current != self.last_min:
            self.errors_per_min.append(self.current_minute_errors)
            self.current_minute_errors = 1
            self.last_min = current
        else:
            self.current_minute_errors += 1

    def _gen_response(self) -> str:
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Server Response</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 min-h-screen flex flex-col items-center justify-center">
            <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full">
                <h1 class="text-2xl font-bold text-gray-900 mb-4">Server Response</h1>
                <div class="bg-green-50 p-4 rounded-md">
                    <p class="text-green-700">Request processed successfully</p>
                    <div class="mt-4 text-sm text-gray-600">
                        <p>Server: {self.host}:{self.port}</p>
                        <p>Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <p>Active Connections: {self.active_connections}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """

    async def health_check(self) -> Dict:
        try:
            async with self._metrics_lock:
                current_time = time.time()
                uptime = current_time - self.start_time
                
                avg_response_time = (
                    statistics.mean(self.response_times)
                    if self.response_times else 0
                )
                
                error_rate = (
                    sum(self.errors_per_min) / 60
                    if self.errors_per_min else 0
                )
                
                recent_requests = sum(
                    1 for t in self.request_times
                    if current_time - t <= 60
                )

            # Getting system metrics
            current_load = await self.get_load()
            
            metrics = {
                "status": "healthy",
                "load": current_load,
                "active_connections": self.active_connections,
                "total_requests": self.total_requests,
                "requests_per_minute": recent_requests,
                "avg_response_time": avg_response_time,
                "error_rate": error_rate,
                "uptime": uptime,
                "error_count": self.error_count
            }
            
            is_healthy = (
                current_load < 90 and
                error_rate < 0.1 and
                avg_response_time < 1.0 and
                self.running
            )
            
            metrics["status"] = "healthy" if is_healthy else "unhealthy"
            return metrics
            
        except Exception as e:
            log_event("ERROR", f"Health Check {self.port}", str(e))
            return {
                "status": "error",
                "error": str(e)
            }

    async def get_metrics(self) -> Dict:
        async with self._metrics_lock:
            return {
                "load": await self.get_load(),
                "active_connections": self.active_connections,
                "total_requests": self.total_requests,
                "error_count": self.error_count,
                "avg_response_time": (
                    statistics.mean(self.response_times)
                    if self.response_times else 0
                ),
                "is_running": self.running
            }

    def start(self):
        self.running = True
        self.start_time = time.time()
        log_event("INFO", f"Server {self.port}", "Started")

    def stop(self):
        self.running = False
        log_event("INFO", f"Server {self.port}", "Stopped")
from typing import List, Dict, Optional, Set, Tuple, NamedTuple
from dataclasses import dataclass
import time
import asyncio
from collections import defaultdict, deque
import statistics
from custom_logging import log_event
from web_server import WebServer
from config import SystemConfig

@dataclass
class ServerHealth:
    last_check: float = 0
    is_healthy: bool = True
    response_times: deque = deque(maxlen=100)
    error_count: int = 0
    consecutive_failures: int = 0
    status_message: str = "Starting"

@dataclass
class MitigationRule:
    created_at: float
    expires_at: float
    action: str
    reason: str
    score: float
    rate_limit: Optional[float] = None

class LoadBalancer:
    def __init__(self, servers: List[WebServer]):
        self.servers = {server: ServerHealth() for server in servers}
        self.connection_counts: Dict[WebServer, int] = defaultdict(int)
        self.ip_rules: Dict[str, MitigationRule] = {}
        self.throttled_ips: Set[str] = set()        
        self.rate_limiters: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))        
        self.total = 0
        self.blocked = 0
        self.request_history: deque = deque(maxlen=1000)        
        config = SystemConfig.get_config()
        self.health_check_interval = config['health_check_interval']
        self.max_response_time = config['max_response_time']
        self.error_threshold = config['thresholds']['error_threshold']
        
        # For thread safety
        self.lock = asyncio.Lock()
        self._running = False
        self._health_check_task = None

    async def start(self):
        self._running = True
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        log_event("INFO", "LoadBalancer", "Started health checker")

    async def stop(self):
        self._running = False
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        log_event("INFO", "LoadBalancer", "Stopped health checker")
        for server in self.servers:
            server.stop()

    async def handle_recommendations(self, recommendations: List[Dict]) -> None:
        try:
            for rec in recommendations:
                await self.add_mitigation_rule(
                    target=rec['target'],
                    action=rec['action'],
                    duration=rec['duration'],
                    reason=rec['reason'],
                    score=rec['score'],
                    rate_limit=rec.get('rate_limit')
                )
        except Exception as e:
            log_event("ERROR", "LoadBalancer", f"Error handling recommendations: {str(e)}")

    async def select_server(self, client_ip: str) -> Tuple[Optional[WebServer], Optional[str]]:
        async with self.lock:
            block_reason = await self._check_mitigation_rules(client_ip)
            if block_reason:
                return None, block_reason

            available_servers = [
                server for server, health in self.servers.items()
                if health.is_healthy and server.running
            ]

            if not available_servers:
                return None, "No healthy servers available"

            selected_server = await self._select_server(available_servers)
            if not selected_server:
                return None, "No servers available"

            self.connection_counts[selected_server] += 1
            self.request_history.append(
                (time.time(), f"{selected_server.host}:{selected_server.port}")
            )

            return selected_server, None

    async def _check_mitigation_rules(self, client_ip: str) -> Optional[str]:        
        await self._clean_expired_rules()
        
        if client_ip in self.ip_rules:
            rule = self.ip_rules[client_ip]
            if rule.action == 'block':
                self.blocked += 1
                return f"IP blocked: {rule.reason} (Score: {rule.score:.2f})"
            elif rule.action == 'throttle':
                if not await self._check_rate_limit(client_ip, rule.rate_limit):
                    self.blocked += 1
                    return f"Rate limit exceeded: {rule.reason}"
            elif rule.action == 'challenge':
                return f"Challenge required: {rule.reason}"
        
        return None

    async def _select_server(self, available_servers: List[WebServer]) -> Optional[WebServer]:
        if not available_servers:
            return None
            
        server_scores = []
        for server in available_servers:
            try:
                metrics = await server.get_metrics()                
                load_score = 1.0 - (metrics["load"] / 100.0)
                conn_score = 1.0 - (self.connection_counts[server] / server.max_connections)
                response_score = 1.0 - min(metrics["avg_response_time"] / self.max_response_time, 1.0)
                
                # Combined weighted score
                score = (
                    load_score * 0.4 +
                    conn_score * 0.4 +
                    response_score * 0.2
                )
                
                server_scores.append((score, server))
                
            except Exception as e:
                log_event("ERROR", "LoadBalancer", f"Error scoring server {server.host}:{server.port}: {str(e)}")
                continue
            
        if not server_scores:
            return None
            
        return max(server_scores, key=lambda x: x[0])[1]

    async def _check_rate_limit(self, target: str, limit: float) -> bool:
        if not limit:
            return True

        current_time = time.time()
        
        self.rate_limiters[target] = deque(
            ts for ts in self.rate_limiters[target]
            if current_time - ts <= 1.0
        )
        
        if len(self.rate_limiters[target]) >= limit:
            return False
            
        self.rate_limiters[target].append(current_time)
        return True

    async def add_mitigation_rule(self, target: str, action: str, duration: int, 
                                reason: str, score: float, rate_limit: Optional[float] = None):
        async with self.lock:
            current_time = time.time()
            
            if target in self.ip_rules:
                existing_rule = self.ip_rules[target]
                if existing_rule.score < score:
                    existing_rule.expires_at = current_time + duration
                    existing_rule.action = action
                    existing_rule.reason = reason
                    existing_rule.score = score
                    existing_rule.rate_limit = rate_limit
                    log_event("INFO", "LoadBalancer", 
                             f"Updated {action} rule for {target}: {reason} (Score: {score:.2f})")
                return

            rule = MitigationRule(
                created_at=current_time,
                expires_at=current_time + duration,
                action=action,
                reason=reason,
                score=score,
                rate_limit=rate_limit if action == 'throttle' else None
            )
            
            self.ip_rules[target] = rule
            if action == 'throttle':
                self.throttled_ips.add(target)
                
            log_event("INFO", "LoadBalancer", 
                     f"Added {action} rule for {target}: {reason} (Score: {score:.2f})")

    async def _clean_expired_rules(self):
        current_time = time.time()
        expired_ips = [
            ip for ip, rule in self.ip_rules.items()
            if current_time >= rule.expires_at
        ]
        for ip in expired_ips:
            rule = self.ip_rules[ip]
            del self.ip_rules[ip]
            if ip in self.rate_limiters:
                del self.rate_limiters[ip]
            self.throttled_ips.discard(ip)
            log_event("INFO", "LoadBalancer", 
                     f"Expired {rule.action} rule for {ip}: {rule.reason}")

    async def release_server(self, server: WebServer):
        async with self.lock:
            if server in self.connection_counts:
                self.connection_counts[server] = max(0, self.connection_counts[server] - 1)

    async def get_metrics(self) -> Dict:
        async with self.lock:
            current_time = time.time()
            
            recent_requests = [r for r in self.request_history 
                             if current_time - r[0] <= 1.0]
            rps = len(recent_requests)
            
            server_metrics = {}
            for server in self.servers:
                try:
                    metrics = await server.get_metrics()
                    health = self.servers[server]
                    
                    server_metrics[f"{server.host}:{server.port}"] = {
                        "load": metrics["load"],
                        "active_connections": metrics["active_connections"],
                        "response_time": statistics.mean(health.response_times) if health.response_times else 0,
                        "is_healthy": health.is_healthy,
                        "status": health.status_message,
                        "error_count": metrics["error_count"]
                    }
                except Exception as e:
                    log_event("ERROR", "LoadBalancer", 
                            f"Error getting metrics from server {server.host}:{server.port}: {str(e)}")
            
            active_rules = [
                {
                    "ip": ip,
                    "action": rule.action,
                    "reason": rule.reason,
                    "score": rule.score,
                    "created_at": rule.created_at,
                    "expires_at": rule.expires_at,
                    "rate_limit": rule.rate_limit,
                    "remaining_time": int(rule.expires_at - current_time)
                }
                for ip, rule in self.ip_rules.items()
                if rule.expires_at > current_time
            ]
            
            return {
                "servers": server_metrics,
                "traffic": {
                    "total": self.total,
                    "blocked_requests": self.blocked,
                    "requests_per_second": rps,
                    "active_connections": sum(count for count in self.connection_counts.values())
                },
                "mitigation": {
                    "active_rules": active_rules,
                    "total_rules": len(self.ip_rules),
                    "throttled_ips": len(self.throttled_ips)
                }
            }

    async def _health_check_loop(self):
        while self._running:
            try:
                async with self.lock:
                    for server, health in self.servers.items():
                        try:
                            metrics = await server.health_check()
                            
                            health.last_check = time.time()
                            if "avg_response_time" in metrics:
                                health.response_times.append(metrics["avg_response_time"])
                            
                            if metrics["status"] == "healthy":
                                health.consecutive_failures = 0
                                health.is_healthy = True
                                health.status_message = "Healthy"
                            else:
                                health.consecutive_failures += 1
                                if health.consecutive_failures >= 3:
                                    health.is_healthy = False
                                    health.status_message = metrics.get("status", "Unhealthy")
                                    log_event("WARNING", "LoadBalancer", 
                                            f"Server {server.host}:{server.port} marked unhealthy: {health.status_message}")
                        except Exception as e:
                            health.consecutive_failures += 1
                            if health.consecutive_failures >= 3:
                                health.is_healthy = False
                                health.status_message = f"Health check failed: {str(e)}"
                                log_event("ERROR", "LoadBalancer", 
                                        f"Health check failed for {server.host}:{server.port}: {str(e)}")
            except Exception as e:
                log_event("ERROR", "LoadBalancer", f"Health check loop error: {str(e)}")
            
            await asyncio.sleep(self.health_check_interval)
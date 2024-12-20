from collections import defaultdict, deque
from dataclasses import dataclass
import asyncio
import time
from typing import DefaultDict, Deque, Dict, List, Optional, Set, Tuple, NamedTuple
from custom_logging import log_event
from config import SystemConfig

@dataclass
class RequestData:
    timestamp: float
    path: str
    method: str
    size: int
    status_code: int

class MitigationRecommendation(NamedTuple):
    target: str  # IP or subnet
    action: str
    duration: int  # seconds
    reason: str
    score: float
    rate_limit: Optional[float] = None

class ConnectionTracker:
    def __init__(self, window_size: int):
        self.window_size = window_size
        self.requests: Deque[RequestData] = deque()
        self.total_requests = 0
        self.failed_requests = 0
        self.bytes_transferred = 0
        self.last_request_time = 0
        self.request_intervals: Deque[float] = deque(maxlen=100)
        self.paths: DefaultDict[str, int] = defaultdict(int)
        self.methods: DefaultDict[str, int] = defaultdict(int)
        self.status_codes: DefaultDict[int, int] = defaultdict(int)
        self.lock = asyncio.Lock()
        self.thresholds = {
        'request_rate': 30,
        'failure_rate': 0.4,
        'pattern_score': 0.85,
        'burst_score': 0.9,
        }
        
        self.durations = {
        'low': 60,
        'medium': 300,
        'high': 900
        }

    async def add_request(self, request: RequestData) -> None:
        async with self.lock:
            current_time = time.time()
            self.requests.append(request)
            self.total_requests += 1
            self.bytes_transferred += request.size
            
            if request.status_code >= 400:
                self.failed_requests += 1
                
            if self.last_request_time > 0:
                interval = current_time - self.last_request_time
                self.request_intervals.append(interval)
                
            self.last_request_time = current_time
            self.paths[request.path] += 1
            self.methods[request.method] += 1
            self.status_codes[request.status_code] += 1
            
            while self.requests and current_time - self.requests[0].timestamp > self.window_size:
                old_req = self.requests.popleft()
                self.total_requests -= 1
                if old_req.status_code >= 400:
                    self.failed_requests -= 1
                self.bytes_transferred -= old_req.size

    async def get_metrics(self) -> Dict:
        async with self.lock:
            current_time = time.time()
            if not self.requests:
                return {
                    "request_rate": 0.0,
                    "failure_rate": 0.0,
                    "pattern_score": 0.0,
                    "burst_score": 0.0
                }

            time_span = current_time - self.requests[0].timestamp
            request_rate = self.total_requests / max(time_span, 1)
            failure_rate = self.failed_requests / max(self.total_requests, 1)

            pattern_score = await self._pattern_score()
            burst_score = await self._burst_score()

            return {
                "request_rate": request_rate,
                "failure_rate": failure_rate,
                "pattern_score": pattern_score,
                "burst_score": burst_score,
                "total_requests": self.total_requests,
                "unique_paths": len(self.paths),
                "unique_methods": len(self.methods),
                "error_count": self.failed_requests
            }

    async def _pattern_score(self) -> float:
        if not self.total_requests or self.total_requests < 5:
            return 0.0

        path_diversity = len(self.paths) / max(self.total_requests, 1)
        method_diversity = len(self.methods) / max(self.total_requests, 1)
        status_diversity = len(self.status_codes) / max(self.total_requests, 1)
        return (1.0 - path_diversity) * 0.3 + (1.0 - method_diversity) * 0.2 + (1.0 - status_diversity) * 0.2

    async def _burst_score(self) -> float:
        if len(self.request_intervals) < 2:
            return 0.0

        intervals = list(self.request_intervals)
        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)

        normalized_variance = min(1.0, variance / (mean_interval ** 2))
        interval_score = 1.0 - min(1.0, mean_interval)
        return (normalized_variance * 0.6 + interval_score * 0.4)

class DDoSDetector:
    def __init__(self, window_size: int = 60):
        self.window_size = window_size
        self.ip_trackers: Dict[str, ConnectionTracker] = {}
        self.suspicious_ips: Set[str] = set()
        self.lock = asyncio.Lock()
        self.total_requests = 0
        self.blocked_requests = 0
        
        config = SystemConfig.get_config()
        self.thresholds = {
            'request_rate': config['rate_limits']['requests_per_second'],
            'failure_rate': 0.3,
            'pattern_score': 0.7,
            'burst_score': 0.8,
        }
        
        self.durations = {
            'low': 300,
            'medium': 900,
            'high': 1800
        }
        
        # Start cleanup task
        self.running = True
        self.cleanup_task = None

    async def start(self):
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        log_event("INFO", "DDoSDetector", "Started cleanup task")

    async def stop(self):
        self.running = False
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        log_event("INFO", "DDoSDetector", "Stopped cleanup task")

    async def record_request(self, ip: str, path: str, method: str, size: int, status_code: int) -> Dict:
        try:
            request = RequestData(
                timestamp=time.time(),
                path=path,
                method=method,
                size=size,
                status_code=status_code
            )

            async with self.lock:
                self.total_requests += 1
                
                if ip not in self.ip_trackers:
                    self.ip_trackers[ip] = ConnectionTracker(self.window_size)
                await self.ip_trackers[ip].add_request(request)
                
                analysis = await self._analyze_ip(ip)
                recommendations = await self._generate_recommendations(ip, analysis)
                
                is_suspicious = any(rec.score >= self.thresholds['pattern_score'] 
                                  for rec in recommendations)
                
                if is_suspicious:
                    self.suspicious_ips.add(ip)
                    self.blocked_requests += 1

                return {
                    "ip": ip,
                    "analysis": analysis,
                    "is_suspicious": is_suspicious,
                    "recommendations": [rec._asdict() for rec in recommendations]
                }

        except Exception as e:
            log_event("ERROR", "DDoSDetector", f"Error recording request: {str(e)}")
            return {
                "ip": ip,
                "is_suspicious": False,
                "analysis": {},
                "recommendations": []
            }

    async def _analyze_ip(self, ip: str) -> Dict:
        tracker = self.ip_trackers[ip]
        return await tracker.get_metrics()

    async def _generate_recommendations(self, ip: str, analysis: Dict) -> List[MitigationRecommendation]:
        recommendations = []
        
        # Check request rate
        request_rate = analysis['request_rate']
        if request_rate > self.thresholds['request_rate']:
            rate_score = min(1.0, request_rate / (self.thresholds['request_rate'] * 2))
            recommendations.append(MitigationRecommendation(
                target=ip,
                action='throttle',
                duration=self._get_duration(rate_score),
                reason=f"High request rate: {request_rate:.1f} req/s",
                score=rate_score,
                rate_limit=self.thresholds['request_rate'] * 0.8
            ))

        if analysis['failure_rate'] > self.thresholds['failure_rate']:
            failure_score = analysis['failure_rate']
            recommendations.append(MitigationRecommendation(
                target=ip,
                action='block',
                duration=self._get_duration(failure_score),
                reason=f"High failure rate: {analysis['failure_rate']*100:.1f}%",
                score=failure_score
            ))

        if analysis['pattern_score'] > self.thresholds['pattern_score']:
            recommendations.append(MitigationRecommendation(
                target=ip,
                action='block',
                duration=self._get_duration(analysis['pattern_score']),
                reason="Suspicious request pattern detected",
                score=analysis['pattern_score']
            ))

        if analysis['burst_score'] > self.thresholds['burst_score']:
            recommendations.append(MitigationRecommendation(
                target=ip,
                action='throttle',
                duration=self._get_duration(analysis['burst_score']),
                reason="Request burst detected",
                score=analysis['burst_score'],
                rate_limit=self.thresholds['request_rate'] * 0.5
            ))

        return recommendations

    def _get_duration(self, score: float) -> int:
        if score >= 0.9:
            return self.durations['high']
        elif score >= 0.7:
            return self.durations['medium']
        return self.durations['low']

    async def get_metrics(self) -> Dict:
        async with self.lock:
            top_offenders = await self._get_top_offenders()
            return {
                "total_ips": len(self.ip_trackers),
                "suspicious_ips": list(self.suspicious_ips),
                "total_requests": self.total_requests,
                "blocked_requests": self.blocked_requests,
                "top_offenders": top_offenders
            }

    async def _get_top_offenders(self, limit: int = 5) -> List[Dict]:
        scores = []
        for ip, tracker in self.ip_trackers.items():
            metrics = await tracker.get_metrics()
            max_score = max(
                metrics['pattern_score'],
                metrics['burst_score'],
                metrics['failure_rate']
            )
            scores.append((ip, max_score, metrics))
        
        return [
            {
                "ip": ip,
                "score": score,
                "metrics": metrics
            }
            for ip, score, metrics in sorted(scores, key=lambda x: x[1], reverse=True)[:limit]
        ]

    async def _cleanup_loop(self) -> None:
        while self.running:
            try:
                await asyncio.sleep(60)  # Cleanup every minute
                
                async with self.lock:
                    # Clean up IP trackers
                    for ip in list(self.ip_trackers.keys()):
                        tracker = self.ip_trackers[ip]
                        if not tracker.requests:
                            del self.ip_trackers[ip]
                            self.suspicious_ips.discard(ip)
                            
            except Exception as e:
                log_event("ERROR", "DDoSDetector", f"Cleanup error: {str(e)}")
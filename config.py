from typing import Dict, Any

class SystemConfig:
    DEFAULT_CONFIG: Dict[str, Any] = {
        'host': '127.0.0.1',
        'server_ports': [8081, 8082, 8083],
        'admin_port': 8000,
        'detection_window': 60,
        'health_check_interval': 5,
        'max_response_time': 2.0,
        'rate_limits': {
            'requests_per_second': 100,
            'connections_per_ip': 50,
            'max_servers': 10
        },
        'thresholds': {
            'cpu_threshold': 80,
            'memory_threshold': 80,
            'error_threshold': 0.1,
            'suspicious_score': 0.7
        },
        'mitigation': {
            'block_duration': 300,
            'challenge_duration': 60,
            'rate_limit_duration': 120
        },
        'security': {
            'admin_username': 'admin',
            'admin_password': 'admin123',
            'session_timeout': 3600
        }
    }

    @classmethod
    def get_config(cls) -> Dict[str, Any]:
        return cls.DEFAULT_CONFIG
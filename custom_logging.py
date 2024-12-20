import logging
import threading
from typing import Optional
from pathlib import Path

class CustomLogger:
    _instance: Optional['CustomLogger'] = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, log_file: str = "logs/system.log", enable_console: bool = True) -> None:
        if hasattr(self, 'logger'):
            return
            
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger("DDoSProtectionSystem")
        self.logger.setLevel(logging.DEBUG)
        
        if not self.logger.handlers:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
            
            if enable_console:
                console_handler = logging.StreamHandler()
                console_handler.setLevel(logging.INFO)
                console_handler.setFormatter(file_formatter)
                self.logger.addHandler(console_handler)

    def log(self, level: str, category: str, message: str) -> None:
        log_message = f"[{category}] {message}"
        level = level.lower()
        
        if level == "debug":
            self.logger.debug(log_message)
        elif level == "info":
            self.logger.info(log_message)
        elif level == "warning":
            self.logger.warning(log_message)
        elif level == "error":
            self.logger.error(log_message)
        elif level == "critical":
            self.logger.critical(log_message)
        else:
            self.logger.info(log_message)

instance = CustomLogger()

def log_event(level: str, category: str, message: str) -> None:
    instance.log(level, category, message)
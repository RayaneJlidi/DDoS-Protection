import logging

class CustomLogger:
    def __init__(self, log_file: str = "system_log.txt", enable_console: bool = True) -> None:
        self.logger = logging.getLogger("DDoSProtectionSystem")
        self.logger.setLevel(logging.DEBUG)

        # Setup file logging
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
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

        if level.lower() == "info":
            self.logger.info(log_message)
        elif level.lower() == "warning":
            self.logger.warning(log_message)
        elif level.lower() == "error":
            self.logger.error(log_message)
        else:
            self.logger.debug(log_message)

# Logger instance for global use
logger_instance = CustomLogger()

# Convenience function for logging events globally.
def log_event(level: str, category: str, message: str) -> None:
    logger_instance.log(level, category, message)

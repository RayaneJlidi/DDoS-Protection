class TrafficMonitor:
    # Detect anomalies based on request rates
    def __init__(self):
        self.baseline = 100  # base requests per second
        self.deviation_threshold = 2.0  # allowed deviation (200%)

    def detect_anomaly(self, current_rate: int) -> bool:
        return (abs(current_rate - self.baseline) / self.baseline) > self.deviation_threshold

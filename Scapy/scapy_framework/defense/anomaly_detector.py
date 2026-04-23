"""Anomaly Detector"""
from collections import defaultdict
import time
from scapy_framework.core.logger import get_logger

logger = get_logger(__name__)

class AnomalyDetector:
    """Basic anomaly detection"""
    def __init__(self, threshold: int = 100, window: int = 60):
        self.threshold = threshold
        self.window = window
        self.packet_counts = defaultdict(list)
    
    def check(self, src_ip: str) -> bool:
        """Check for anomalies"""
        now = time.time()
        self.packet_counts[src_ip].append(now)
        
        # Remove old entries
        self.packet_counts[src_ip] = [t for t in self.packet_counts[src_ip] 
                                       if now - t < self.window]
        
        count = len(self.packet_counts[src_ip])
        if count > self.threshold:
            logger.warning(f"Anomaly detected: {src_ip} sent {count} packets in {self.window}s")
            return True
        return False

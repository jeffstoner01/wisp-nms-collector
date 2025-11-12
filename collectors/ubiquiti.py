"""
Ubiquiti Device Collector
Collects data from Ubiquiti devices (airMAX, LTU, etc.)
"""

import logging
from typing import Dict, Any
from .snmp import SNMPCollector

logger = logging.getLogger(__name__)


class UbiquitiCollector(SNMPCollector):
    """Collector for Ubiquiti devices - extends generic SNMP collector"""
    
    # Ubiquiti-specific OIDs can be added here
    UBNT_OIDS = {
        'radioName': '1.3.6.1.4.1.41112.1.4.1.1.3.1',
        'radioFreq': '1.3.6.1.4.1.41112.1.4.1.1.4.1',
        'radioSignal': '1.3.6.1.4.1.41112.1.4.5.1.2.1',
        'radioNoise': '1.3.6.1.4.1.41112.1.4.5.1.3.1',
        'radioTxPower': '1.3.6.1.4.1.41112.1.4.5.1.5.1',
    }
    
    def __init__(self, device_config: Dict[str, Any]):
        """Initialize Ubiquiti collector"""
        super().__init__(device_config)
        self.OIDS.update(self.UBNT_OIDS)
    
    def collect_metrics(self) -> Dict[str, Any]:
        """Collect device metrics including wireless stats"""
        from .metrics_collector import MetricsCollector
        
        metrics = super().collect_metrics()
        
        # Collect comprehensive metrics (throughput, signal, wireless, etc.)
        try:
            snmp_version = self.config.get('snmpVersion', '2c')
            metrics_collector = MetricsCollector(self.ip, self.community, 'ubiquiti', snmp_version)
            comprehensive = metrics_collector.collect_all_metrics()
            
            # Add latency
            if comprehensive.get('latency'):
                metrics['latency'] = comprehensive['latency']
            
            # Add wireless metrics
            if comprehensive.get('wireless'):
                metrics.update(comprehensive['wireless'])
            
            # Add interface metrics
            if comprehensive.get('interfaces'):
                metrics['interfaces'] = comprehensive['interfaces']
        except Exception as e:
            logger.error(f"Error collecting comprehensive metrics: {e}")
        
        return metrics
    
    def collect(self) -> Dict[str, Any]:
        """Main collection method"""
        logger.info(f"Collecting from Ubiquiti device: {self.ip}")
        result = super().collect()
        
        # Add Ubiquiti-specific device info
        if result['device'] and result['device']['status'] == 'online':
            result['device']['vendor'] = 'ubiquiti'
            if 'family' in self.config:
                result['device']['family'] = self.config['family']
        
        return result

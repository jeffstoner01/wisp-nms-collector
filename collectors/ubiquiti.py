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
        metrics = super().collect_metrics()
        
        # Collect wireless-specific metrics
        signal = self.snmp_get(self.UBNT_OIDS['radioSignal'])
        if signal:
            try:
                metrics['signalStrength'] = int(signal)
            except:
                pass
        
        # Add more Ubiquiti-specific metrics as needed
        
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

"""
Ubiquiti Device Collector
Collects data from Ubiquiti devices (airMAX, LTU, etc.)
"""

import logging
import subprocess
from typing import Dict, Any, Optional
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
    
    def snmp_get(self, oid: str) -> Optional[str]:
        """Execute SNMP GET - airMAX devices typically use SNMPv1"""
        try:
            snmp_version = self.config.get('snmpVersion', '1')
            cmd = [
                'snmpget',
                '-v', snmp_version,
                '-c', self.community,
                '-t', '3',
                '-r', '2',
                '-Oqv',
                self.ip,
                oid
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception as e:
            logger.debug(f"SNMP GET error for {self.ip} {oid}: {e}")
        return None
    
    def collect_metrics(self) -> Dict[str, Any]:
        """Collect airMAX-specific metrics"""
        metrics = {}
        
        try:
            # Get wireless metrics from airMAX MIB
            # Frequency (MHz)
            freq = self.snmp_get('1.3.6.1.4.1.41112.1.4.1.1.4.1')
            if freq:
                try:
                    metrics['frequency'] = int(freq)
                except ValueError:
                    pass
            
            # TX Power (dBm)
            tx_power = self.snmp_get('1.3.6.1.4.1.41112.1.4.1.1.6.1')
            if tx_power:
                try:
                    metrics['txPower'] = int(tx_power)
                except ValueError:
                    pass
            
            # Signal Strength (dBm) - from radio stats table
            signal = self.snmp_get('1.3.6.1.4.1.41112.1.4.5.1.5.1')
            if signal:
                try:
                    metrics['signalStrength'] = int(signal)
                except ValueError:
                    pass
            
            # Link capacity (Mbps)
            capacity = self.snmp_get('1.3.6.1.4.1.41112.1.4.5.1.6.1')
            if capacity:
                try:
                    metrics['capacity'] = int(capacity)
                except ValueError:
                    pass
            
            # Airtime utilization
            airtime = self.snmp_get('1.3.6.1.4.1.41112.1.4.5.1.14.1')
            if airtime:
                try:
                    metrics['airtime'] = int(airtime)
                except ValueError:
                    pass
            
            # Get interface metrics using standard MIBs
            from .metrics_collector import MetricsCollector
            snmp_version = self.config.get('snmpVersion', '1')
            mc = MetricsCollector(self.ip, self.community, 'ubiquiti', snmp_version)
            
            # Get interface metrics
            interfaces = mc.collect_interface_metrics()
            if interfaces:
                metrics['interfaces'] = interfaces
            
            # Get latency
            latency = mc.ping_latency()
            if latency:
                metrics['latency'] = latency
            
        except Exception as e:
            logger.error(f"Error collecting airMAX metrics from {self.ip}: {e}")
        
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

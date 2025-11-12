"""
Ubiquiti Wave Device Collector
Collects data from Ubiquiti Wave devices using airFiber MIB (1.3.6.1.4.1.41112.1.11.*)
Wave devices use different OIDs than airMAX devices
"""

import logging
import subprocess
from typing import Dict, Any, Optional
from .snmp import SNMPCollector

logger = logging.getLogger(__name__)


class UbiquitiWaveCollector(SNMPCollector):
    """Collector for Ubiquiti Wave devices (Wave AP, Wave LR, etc.)"""
    
    # Ubiquiti airFiber/Wave MIB OIDs (1.3.6.1.4.1.41112.1.11.*)
    WAVE_OIDS = {
        # Radio info (1.11.1.1.*)
        'waveRadioFreq': '1.3.6.1.4.1.41112.1.11.1.1.2.1',      # Frequency in MHz
        'waveRadioChannel': '1.3.6.1.4.1.41112.1.11.1.1.3.1',   # Channel width
        
        # Device info (1.11.1.2.*)
        'waveName': '1.3.6.1.4.1.41112.1.11.1.2.2.1',           # Model name
        'waveHostname': '1.3.6.1.4.1.41112.1.11.1.2.3.1',       # Hostname
        'waveTemperature': '1.3.6.1.4.1.41112.1.11.1.2.5.1',    # Temperature in Celsius
        'waveUptime': '1.3.6.1.4.1.41112.1.11.1.2.7.1',         # Uptime in timeticks
        
        # Station/Link metrics (1.11.1.3.1.*) - indexed by station MAC
        'waveStaSignal': '1.3.6.1.4.1.41112.1.11.1.3.1.3',      # Signal strength in dBm
        'waveStaTxRate': '1.3.6.1.4.1.41112.1.11.1.3.1.4',      # TX rate
        'waveStaRxRate': '1.3.6.1.4.1.41112.1.11.1.3.1.5',      # RX rate
        'waveStaTxBytes': '1.3.6.1.4.1.41112.1.11.1.3.1.10',    # TX bytes counter
        'waveStaRxBytes': '1.3.6.1.4.1.41112.1.11.1.3.1.9',     # RX bytes counter
        'waveStaFreq': '1.3.6.1.4.1.41112.1.11.1.3.1.15',       # Frequency in MHz
        'waveStaChannelWidth': '1.3.6.1.4.1.41112.1.11.1.3.1.16', # Channel width
        'waveStaRemoteSignal': '1.3.6.1.4.1.41112.1.11.1.3.1.18', # Remote signal
    }
    
    def __init__(self, device_config: Dict[str, Any]):
        """Initialize Wave collector"""
        super().__init__(device_config)
        self.OIDS.update(self.WAVE_OIDS)
    
    def snmp_get(self, oid: str) -> Optional[str]:
        """Execute SNMP GET - Wave devices support both v1 and v2c"""
        try:
            snmp_version = self.config.get('snmpVersion', '2c')
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
    
    def snmp_walk(self, oid: str) -> list:
        """Execute SNMP WALK"""
        results = []
        try:
            snmp_version = self.config.get('snmpVersion', '2c')
            cmd = [
                'snmpwalk',
                '-v', snmp_version,
                '-c', self.community,
                '-t', '3',
                '-r', '2',
                '-Oqn',
                self.ip,
                oid
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split(' ', 1)
                        if len(parts) == 2:
                            results.append((parts[0], parts[1]))
        except Exception as e:
            logger.debug(f"SNMP WALK error for {self.ip} {oid}: {e}")
        return results
    
    def collect_metrics(self) -> Dict[str, Any]:
        """Collect Wave-specific metrics"""
        metrics = {}
        
        try:
            # Get temperature
            temp = self.snmp_get(self.WAVE_OIDS['waveTemperature'])
            if temp:
                try:
                    metrics['temperature'] = int(temp)
                except ValueError:
                    pass
            
            # Get uptime
            uptime = self.snmp_get(self.WAVE_OIDS['waveUptime'])
            if uptime:
                try:
                    # Convert timeticks to seconds
                    timeticks = int(uptime.split('(')[1].split(')')[0]) if '(' in uptime else int(uptime)
                    metrics['uptime'] = timeticks // 100
                except (ValueError, IndexError):
                    pass
            
            # Get station metrics (for PtP links, there's usually one station)
            # Walk the station table to get wireless metrics
            signals = self.snmp_walk(self.WAVE_OIDS['waveStaSignal'])
            tx_rates = self.snmp_walk(self.WAVE_OIDS['waveStaTxRate'])
            rx_rates = self.snmp_walk(self.WAVE_OIDS['waveStaRxRate'])
            frequencies = self.snmp_walk(self.WAVE_OIDS['waveStaFreq'])
            channel_widths = self.snmp_walk(self.WAVE_OIDS['waveStaChannelWidth'])
            tx_bytes = self.snmp_walk(self.WAVE_OIDS['waveStaTxBytes'])
            rx_bytes = self.snmp_walk(self.WAVE_OIDS['waveStaRxBytes'])
            
            # For PtP links, use the first (and usually only) station's metrics
            if signals:
                try:
                    metrics['signalStrength'] = int(signals[0][1])
                except (ValueError, IndexError):
                    pass
            
            if tx_rates:
                try:
                    metrics['txRate'] = int(tx_rates[0][1]) * 1000000  # Convert to bps
                except (ValueError, IndexError):
                    pass
            
            if rx_rates:
                try:
                    metrics['rxRate'] = int(rx_rates[0][1]) * 1000000  # Convert to bps
                except (ValueError, IndexError):
                    pass
            
            if frequencies:
                try:
                    metrics['frequency'] = int(frequencies[0][1])
                except (ValueError, IndexError):
                    pass
            
            if channel_widths:
                try:
                    metrics['channelWidth'] = int(channel_widths[0][1])
                except (ValueError, IndexError):
                    pass
            
            if tx_bytes:
                try:
                    metrics['txBytes'] = int(tx_bytes[0][1])
                except (ValueError, IndexError):
                    pass
            
            if rx_bytes:
                try:
                    metrics['rxBytes'] = int(rx_bytes[0][1])
                except (ValueError, IndexError):
                    pass
            
            # Count connected stations
            metrics['stationsCount'] = len(signals)
            
            # Collect interface metrics using standard MIBs
            from .metrics_collector import MetricsCollector
            snmp_version = self.config.get('snmpVersion', '2c')
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
            logger.error(f"Error collecting Wave metrics from {self.ip}: {e}")
        
        return metrics
    
    def collect(self) -> Dict[str, Any]:
        """Main collection method"""
        logger.info(f"Collecting from Ubiquiti Wave device: {self.ip}")
        result = super().collect()
        
        # Add Wave-specific device info
        if result['device'] and result['device']['status'] == 'online':
            result['device']['vendor'] = 'ubiquiti'
            result['device']['family'] = 'wave'
        
        return result

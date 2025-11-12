"""
Comprehensive Metrics Collector
Collects detailed metrics from network devices including:
- Throughput (tx/rx rates)
- Signal strength
- Frequency/channel
- Airtime/utilization
- Latency
- Capacity
- Wireless stations
- Link quality
"""

import logging
import subprocess
import re
from typing import Dict, Any, List, Optional
import time

logger = logging.getLogger(__name__)


class MetricsCollector:
    """Collects comprehensive metrics from network devices"""
    
    # Standard interface MIB OIDs
    IF_DESCR = '1.3.6.1.2.1.2.2.1.2'  # ifDescr
    IF_SPEED = '1.3.6.1.2.1.2.2.1.5'  # ifSpeed
    IF_IN_OCTETS = '1.3.6.1.2.1.2.2.1.10'  # ifInOctets
    IF_OUT_OCTETS = '1.3.6.1.2.1.2.2.1.16'  # ifOutOctets
    IF_IN_ERRORS = '1.3.6.1.2.1.2.2.1.14'  # ifInErrors
    IF_OUT_ERRORS = '1.3.6.1.2.1.2.2.1.20'  # ifOutErrors
    
    # MikroTik Wireless OIDs
    MT_WIRELESS_SIGNAL = '1.3.6.1.4.1.14988.1.1.1.1.1.4'  # mtxrWlRtabStrength
    MT_WIRELESS_TX_RATE = '1.3.6.1.4.1.14988.1.1.1.1.1.2'  # mtxrWlRtabTxRate
    MT_WIRELESS_RX_RATE = '1.3.6.1.4.1.14988.1.1.1.1.1.3'  # mtxrWlRtabRxRate
    MT_WIRELESS_FREQ = '1.3.6.1.4.1.14988.1.1.1.3.1.7'  # mtxrWlApFreq
    MT_WIRELESS_CLIENTS = '1.3.6.1.4.1.14988.1.1.1.3.1.6'  # mtxrWlApClientCount
    
    # Ubiquiti AirMAX OIDs
    UBNT_RADIO_SIGNAL = '1.3.6.1.4.1.41112.1.4.5.1.2'  # ubntRadioRssi
    UBNT_RADIO_FREQ = '1.3.6.1.4.1.41112.1.4.1.1.4'  # ubntRadioFreq
    UBNT_RADIO_TXPOWER = '1.3.6.1.4.1.41112.1.4.1.1.5'  # ubntRadioTxPower
    UBNT_RADIO_DISTANCE = '1.3.6.1.4.1.41112.1.4.2.1.5'  # ubntRadioDistance
    UBNT_RADIO_CAPACITY = '1.3.6.1.4.1.41112.1.4.5.1.6'  # ubntRadioCapacity
    UBNT_RADIO_AIRTIME = '1.3.6.1.4.1.41112.1.4.5.1.14'  # ubntRadioAirtime
    UBNT_STATION_COUNT = '1.3.6.1.4.1.41112.1.4.7.1.1'  # ubntStaCount
    
    def __init__(self, ip: str, community: str = 'public', vendor: str = 'generic', snmp_version: str = '2c'):
        """Initialize metrics collector"""
        self.ip = ip
        self.community = community
        self.vendor = vendor.lower()
        self.snmp_version = snmp_version  # Store preferred SNMP version
        self.previous_counters = {}
        
    def snmp_get(self, oid: str, version: Optional[int] = None) -> Optional[str]:
        """Execute SNMP GET using CLI tools"""
        # Use device's preferred version if not specified
        if version is None:
            version = 1 if self.snmp_version == '1' else 2
        
        try:
            version_str = f'{version}c' if version == 2 else '1'
            cmd = [
                'snmpget',
                '-v', version_str,
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
            # Try SNMPv1 fallback only if we started with v2
            if version == 2:
                return self.snmp_get(oid, version=1)
        except Exception as e:
            logger.debug(f"SNMP GET error for {self.ip} {oid}: {e}")
        return None
    
    def snmp_walk(self, oid: str, version: Optional[int] = None) -> List[tuple]:
        """Execute SNMP WALK using CLI tools"""
        # Use device's preferred version if not specified
        if version is None:
            version = 1 if self.snmp_version == '1' else 2
        
        results = []
        try:
            version_str = f'{version}c' if version == 2 else '1'
            cmd = [
                'snmpwalk',
                '-v', version_str,
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
            elif version == 2:
                # Try SNMPv1 fallback
                return self.snmp_walk(oid, version=1)
        except Exception as e:
            logger.debug(f"SNMP WALK error for {self.ip} {oid}: {e}")
        return results
    
    def ping_latency(self) -> Optional[float]:
        """Measure ping latency to device"""
        try:
            cmd = ['ping', '-c', '3', '-W', '2', self.ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # Parse average latency from output
                match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', result.stdout)
                if match:
                    return float(match.group(1))
        except Exception as e:
            logger.debug(f"Ping error for {self.ip}: {e}")
        return None
    
    def collect_interface_metrics(self) -> List[Dict[str, Any]]:
        """Collect detailed interface metrics"""
        metrics = []
        
        try:
            # Get interface descriptions
            if_descrs = self.snmp_walk(self.IF_DESCR)
            if_speeds = self.snmp_walk(self.IF_SPEED)
            in_octets = self.snmp_walk(self.IF_IN_OCTETS)
            out_octets = self.snmp_walk(self.IF_OUT_OCTETS)
            in_errors = self.snmp_walk(self.IF_IN_ERRORS)
            out_errors = self.snmp_walk(self.IF_OUT_ERRORS)
            
            # Build interface map
            interfaces = {}
            for oid, descr in if_descrs:
                if_index = oid.split('.')[-1]
                interfaces[if_index] = {
                    'name': descr.strip('"'),
                    'index': if_index
                }
            
            # Add speeds
            for oid, speed in if_speeds:
                if_index = oid.split('.')[-1]
                if if_index in interfaces:
                    try:
                        # Speed is in bits per second
                        interfaces[if_index]['speed'] = int(speed)
                    except:
                        pass
            
            # Add counters
            for oid, octets in in_octets:
                if_index = oid.split('.')[-1]
                if if_index in interfaces:
                    try:
                        interfaces[if_index]['rxBytes'] = int(octets)
                    except:
                        pass
            
            for oid, octets in out_octets:
                if_index = oid.split('.')[-1]
                if if_index in interfaces:
                    try:
                        interfaces[if_index]['txBytes'] = int(octets)
                    except:
                        pass
            
            for oid, errors in in_errors:
                if_index = oid.split('.')[-1]
                if if_index in interfaces:
                    try:
                        interfaces[if_index]['rxErrors'] = int(errors)
                    except:
                        pass
            
            for oid, errors in out_errors:
                if_index = oid.split('.')[-1]
                if if_index in interfaces:
                    try:
                        interfaces[if_index]['txErrors'] = int(errors)
                    except:
                        pass
            
            # Calculate throughput rates if we have previous counters
            current_time = time.time()
            for if_index, iface in interfaces.items():
                key = f"{self.ip}:{if_index}"
                
                if key in self.previous_counters:
                    prev_time, prev_rx, prev_tx = self.previous_counters[key]
                    time_delta = current_time - prev_time
                    
                    if time_delta > 0:
                        rx_bytes = iface.get('rxBytes', 0)
                        tx_bytes = iface.get('txBytes', 0)
                        
                        # Calculate rates in bits per second
                        rx_rate = ((rx_bytes - prev_rx) * 8) / time_delta
                        tx_rate = ((tx_bytes - prev_tx) * 8) / time_delta
                        
                        iface['rxRate'] = max(0, int(rx_rate))  # bps
                        iface['txRate'] = max(0, int(tx_rate))  # bps
                        
                        # Calculate utilization if speed is known
                        if 'speed' in iface and iface['speed'] > 0:
                            iface['rxUtilization'] = min(100, (rx_rate / iface['speed']) * 100)
                            iface['txUtilization'] = min(100, (tx_rate / iface['speed']) * 100)
                
                # Store current counters for next iteration
                self.previous_counters[key] = (
                    current_time,
                    iface.get('rxBytes', 0),
                    iface.get('txBytes', 0)
                )
                
                metrics.append(iface)
        
        except Exception as e:
            logger.error(f"Error collecting interface metrics from {self.ip}: {e}")
        
        return metrics
    
    def collect_mikrotik_wireless(self) -> Dict[str, Any]:
        """Collect MikroTik wireless metrics"""
        wireless = {}
        
        try:
            # Signal strength
            signals = self.snmp_walk(self.MT_WIRELESS_SIGNAL)
            if signals:
                # Get average signal from all clients
                signal_values = []
                for oid, value in signals:
                    try:
                        signal_values.append(int(value))
                    except:
                        pass
                if signal_values:
                    wireless['signal'] = sum(signal_values) // len(signal_values)
            
            # TX/RX rates
            tx_rates = self.snmp_walk(self.MT_WIRELESS_TX_RATE)
            rx_rates = self.snmp_walk(self.MT_WIRELESS_RX_RATE)
            
            if tx_rates:
                tx_values = []
                for oid, value in tx_rates:
                    try:
                        # Rates are in 100kbps units
                        tx_values.append(int(value) * 100000)
                    except:
                        pass
                if tx_values:
                    wireless['txRate'] = sum(tx_values) // len(tx_values)
            
            if rx_rates:
                rx_values = []
                for oid, value in rx_rates:
                    try:
                        rx_values.append(int(value) * 100000)
                    except:
                        pass
                if rx_values:
                    wireless['rxRate'] = sum(rx_values) // len(rx_values)
            
            # Frequency
            freqs = self.snmp_walk(self.MT_WIRELESS_FREQ)
            if freqs:
                for oid, value in freqs:
                    try:
                        wireless['frequency'] = int(value)
                        break
                    except:
                        pass
            
            # Client count
            clients = self.snmp_walk(self.MT_WIRELESS_CLIENTS)
            if clients:
                total_clients = 0
                for oid, value in clients:
                    try:
                        total_clients += int(value)
                    except:
                        pass
                wireless['stationsCount'] = total_clients
        
        except Exception as e:
            logger.error(f"Error collecting MikroTik wireless metrics from {self.ip}: {e}")
        
        return wireless
    
    def collect_ubiquiti_wireless(self) -> Dict[str, Any]:
        """Collect Ubiquiti wireless metrics"""
        wireless = {}
        
        try:
            # Signal strength (RSSI)
            signal = self.snmp_get(self.UBNT_RADIO_SIGNAL)
            if signal:
                try:
                    wireless['signal'] = int(signal)
                except:
                    pass
            
            # Frequency
            freq = self.snmp_get(self.UBNT_RADIO_FREQ)
            if freq:
                try:
                    wireless['frequency'] = int(freq)
                except:
                    pass
            
            # TX Power
            tx_power = self.snmp_get(self.UBNT_RADIO_TXPOWER)
            if tx_power:
                try:
                    wireless['txPower'] = int(tx_power)
                except:
                    pass
            
            # Distance
            distance = self.snmp_get(self.UBNT_RADIO_DISTANCE)
            if distance:
                try:
                    wireless['distance'] = int(distance)
                except:
                    pass
            
            # Capacity
            capacity = self.snmp_get(self.UBNT_RADIO_CAPACITY)
            if capacity:
                try:
                    wireless['capacity'] = int(capacity)
                except:
                    pass
            
            # Airtime
            airtime = self.snmp_get(self.UBNT_RADIO_AIRTIME)
            if airtime:
                try:
                    wireless['airtime'] = int(airtime)
                except:
                    pass
            
            # Station count
            stations = self.snmp_get(self.UBNT_STATION_COUNT)
            if stations:
                try:
                    wireless['stationsCount'] = int(stations)
                except:
                    pass
        
        except Exception as e:
            logger.error(f"Error collecting Ubiquiti wireless metrics from {self.ip}: {e}")
        
        return wireless
    
    def collect_all_metrics(self) -> Dict[str, Any]:
        """Collect all available metrics"""
        metrics = {
            'timestamp': int(time.time()),
            'interfaces': [],
            'wireless': {},
            'latency': None
        }
        
        try:
            # Collect latency
            latency = self.ping_latency()
            if latency:
                metrics['latency'] = latency
            
            # Collect interface metrics
            interfaces = self.collect_interface_metrics()
            if interfaces:
                metrics['interfaces'] = interfaces
            
            # Collect wireless metrics based on vendor
            if self.vendor == 'mikrotik':
                wireless = self.collect_mikrotik_wireless()
                if wireless:
                    metrics['wireless'] = wireless
            elif self.vendor == 'ubiquiti':
                wireless = self.collect_ubiquiti_wireless()
                if wireless:
                    metrics['wireless'] = wireless
        
        except Exception as e:
            logger.error(f"Error collecting metrics from {self.ip}: {e}")
        
        return metrics

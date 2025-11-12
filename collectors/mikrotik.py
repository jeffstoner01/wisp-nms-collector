"""
MikroTik Device Collector
Collects data from MikroTik devices via SNMP and RouterOS API
Compatible with pysnmp 7.x
"""

import logging
from typing import Dict, Any, List, Optional
import time

# pysnmp 7.x imports
from pysnmp.hlapi.v3arch.asyncio import *
import asyncio

logger = logging.getLogger(__name__)


class MikroTikCollector:
    """Collector for MikroTik devices"""
    
    # Common MikroTik SNMP OIDs
    OIDS = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysUpTime': '1.3.6.1.2.1.1.3.0',
        'sysName': '1.3.6.1.2.1.1.5.0',
        'cpuLoad': '1.3.6.1.2.1.25.3.3.1.2.1',  # HOST-RESOURCES-MIB
        'memoryTotal': '1.3.6.1.2.1.25.2.3.1.5.65536',
        'memoryUsed': '1.3.6.1.2.1.25.2.3.1.6.65536',
        'temperature': '1.3.6.1.4.1.14988.1.1.3.10.0',  # MikroTik specific
        'voltage': '1.3.6.1.4.1.14988.1.1.3.8.0',
        'ifNumber': '1.3.6.1.2.1.2.1.0',
    }
    
    def __init__(self, device_config: Dict[str, Any]):
        """Initialize MikroTik collector"""
        self.config = device_config
        self.ip = device_config['ip']
        self.device_id = device_config.get('deviceId', self.ip)
        self.snmp_config = device_config.get('snmp', {})
        self.community = self.snmp_config.get('community', 'public')
        self.port = self.snmp_config.get('port', 161)
        
    async def snmp_get_async(self, oid: str) -> Optional[str]:
        """Perform async SNMP GET request"""
        try:
            errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
                SnmpEngine(),
                CommunityData(self.community),
                await UdpTransportTarget.create((self.ip, self.port), timeout=5, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            
            if errorIndication:
                logger.error(f"SNMP error from {self.ip}: {errorIndication}")
                return None
            elif errorStatus:
                logger.error(f"SNMP error from {self.ip}: {errorStatus}")
                return None
            else:
                for varBind in varBinds:
                    return str(varBind[1])
        except Exception as e:
            logger.error(f"SNMP exception for {self.ip}: {e}")
            return None
    
    def snmp_get(self, oid: str) -> Optional[str]:
        """Synchronous wrapper for SNMP GET"""
        try:
            return asyncio.run(self.snmp_get_async(oid))
        except Exception as e:
            logger.error(f"SNMP sync error for {self.ip}: {e}")
            return None
    
    async def snmp_walk_async(self, oid: str) -> List[tuple]:
        """Perform async SNMP WALK request"""
        results = []
        try:
            async for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
                SnmpEngine(),
                CommunityData(self.community),
                await UdpTransportTarget.create((self.ip, self.port), timeout=5, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            ):
                if errorIndication or errorStatus:
                    break
                for varBind in varBinds:
                    results.append((str(varBind[0]), str(varBind[1])))
        except Exception as e:
            logger.error(f"SNMP walk exception for {self.ip}: {e}")
        
        return results
    
    def snmp_walk(self, oid: str) -> List[tuple]:
        """Synchronous wrapper for SNMP WALK"""
        try:
            return asyncio.run(self.snmp_walk_async(oid))
        except Exception as e:
            logger.error(f"SNMP walk sync error for {self.ip}: {e}")
            return []
    
    def collect_device_info(self) -> Dict[str, Any]:
        """Collect basic device information"""
        device_info = {
            'deviceId': self.device_id,
            'name': self.config.get('name', self.ip),
            'ip': self.ip,
            'vendor': 'mikrotik',
            'deviceType': self.config.get('type', 'router'),
            'status': 'unknown'
        }
        
        # Get system description
        sys_descr = self.snmp_get(self.OIDS['sysDescr'])
        if sys_descr:
            device_info['status'] = 'online'
            # Parse model from sysDescr (e.g., "RouterOS RB750Gr3")
            if 'RouterOS' in sys_descr:
                parts = sys_descr.split()
                if len(parts) >= 2:
                    device_info['model'] = parts[1]
                device_info['firmwareVersion'] = sys_descr
        else:
            device_info['status'] = 'offline'
            return device_info
        
        # Get system name
        sys_name = self.snmp_get(self.OIDS['sysName'])
        if sys_name and sys_name != device_info['name']:
            device_info['name'] = sys_name
        
        return device_info
    
    def collect_metrics(self) -> Dict[str, Any]:
        """Collect device metrics"""
        from .metrics_collector import MetricsCollector
        
        metrics = {}
        
        # CPU usage
        cpu_load = self.snmp_get(self.OIDS['cpuLoad'])
        if cpu_load:
            try:
                metrics['cpuUsage'] = int(cpu_load)
            except:
                pass
        
        # Memory usage
        mem_total = self.snmp_get(self.OIDS['memoryTotal'])
        mem_used = self.snmp_get(self.OIDS['memoryUsed'])
        if mem_total and mem_used:
            try:
                total = int(mem_total)
                used = int(mem_used)
                if total > 0:
                    metrics['memoryUsage'] = int((used / total) * 100)
            except:
                pass
        
        # Uptime
        uptime = self.snmp_get(self.OIDS['sysUpTime'])
        if uptime:
            try:
                # Convert timeticks to seconds
                metrics['uptime'] = int(uptime) // 100
            except:
                pass
        
        # Temperature (MikroTik specific)
        temp = self.snmp_get(self.OIDS['temperature'])
        if temp:
            try:
                # Temperature is in tenths of degrees Celsius
                metrics['temperature'] = int(temp) // 10
            except:
                pass
        
        # Collect comprehensive metrics (throughput, signal, wireless, etc.)
        try:
            metrics_collector = MetricsCollector(self.ip, self.community, 'mikrotik')
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
    
    def collect_interface_stats(self) -> Dict[str, Any]:
        """Collect interface statistics"""
        stats = {
            'rxBytes': 0,
            'txBytes': 0,
            'rxPackets': 0,
            'txPackets': 0
        }
        
        try:
            # Get all interface in octets
            in_octets = self.snmp_walk('1.3.6.1.2.1.2.2.1.10')
            out_octets = self.snmp_walk('1.3.6.1.2.1.2.2.1.16')
            in_packets = self.snmp_walk('1.3.6.1.2.1.2.2.1.11')
            out_packets = self.snmp_walk('1.3.6.1.2.1.2.2.1.17')
            
            # Sum all interfaces
            for oid, value in in_octets:
                try:
                    stats['rxBytes'] += int(value)
                except:
                    pass
            
            for oid, value in out_octets:
                try:
                    stats['txBytes'] += int(value)
                except:
                    pass
            
            for oid, value in in_packets:
                try:
                    stats['rxPackets'] += int(value)
                except:
                    pass
            
            for oid, value in out_packets:
                try:
                    stats['txPackets'] += int(value)
                except:
                    pass
        except Exception as e:
            logger.error(f"Error collecting interface stats from {self.ip}: {e}")
        
        return stats
    
    def collect_snmp_data(self) -> List[Dict[str, Any]]:
        """Collect raw SNMP data for storage"""
        snmp_data = []
        
        for name, oid in self.OIDS.items():
            value = self.snmp_get(oid)
            if value:
                snmp_data.append({
                    'oid': oid,
                    'value': value,
                    'description': name,
                    'family': 'mikrotik'
                })
        
        return snmp_data
    
    def collect(self) -> Dict[str, Any]:
        """Main collection method"""
        logger.info(f"Collecting from MikroTik device: {self.ip}")
        
        result = {
            'device': None,
            'metrics': [],
            'snmp_data': [],
            'logs': []
        }
        
        try:
            # Collect device info
            device_info = self.collect_device_info()
            result['device'] = device_info
            
            if device_info['status'] == 'offline':
                logger.warning(f"Device {self.ip} is offline")
                return result
            
            # Collect metrics
            metrics = self.collect_metrics()
            if metrics:
                # Note: deviceId will be filled in by the API after device registration
                result['metrics'] = [metrics]
            
            # Collect raw SNMP data
            snmp_data = self.collect_snmp_data()
            if snmp_data:
                result['snmp_data'] = snmp_data
            
            logger.info(f"Successfully collected data from {self.ip}")
            
        except Exception as e:
            logger.error(f"Error collecting from MikroTik {self.ip}: {e}")
            result['logs'].append({
                'level': 'error',
                'source': self.ip,
                'message': f"Collection error: {str(e)}",
                'category': 'collector'
            })
        
        return result

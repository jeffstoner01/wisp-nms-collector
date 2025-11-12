"""
Generic SNMP Collector
Works with any SNMP-enabled device
Compatible with pysnmp 7.x
"""

import logging
from typing import Dict, Any, List, Optional
import asyncio

# pysnmp 7.x imports
from pysnmp.hlapi.v3arch.asyncio import *

logger = logging.getLogger(__name__)


class SNMPCollector:
    """Generic SNMP collector for any device"""
    
    # Standard SNMP OIDs (RFC 1213 - MIB-II)
    OIDS = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysObjectID': '1.3.6.1.2.1.1.2.0',
        'sysUpTime': '1.3.6.1.2.1.1.3.0',
        'sysContact': '1.3.6.1.2.1.1.4.0',
        'sysName': '1.3.6.1.2.1.1.5.0',
        'sysLocation': '1.3.6.1.2.1.1.6.0',
    }
    
    def __init__(self, device_config: Dict[str, Any]):
        """Initialize SNMP collector"""
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
            
            if errorIndication or errorStatus:
                return None
            
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
            'vendor': self.config.get('vendor', 'generic'),
            'deviceType': self.config.get('type', 'other'),
            'status': 'unknown'
        }
        
        # Get system description
        sys_descr = self.snmp_get(self.OIDS['sysDescr'])
        if sys_descr:
            device_info['status'] = 'online'
            device_info['firmwareVersion'] = sys_descr
        else:
            device_info['status'] = 'offline'
            return device_info
        
        # Get system name
        sys_name = self.snmp_get(self.OIDS['sysName'])
        if sys_name:
            device_info['name'] = sys_name
        
        return device_info
    
    def collect_metrics(self) -> Dict[str, Any]:
        """Collect device metrics"""
        metrics = {}
        
        # Uptime
        uptime = self.snmp_get(self.OIDS['sysUpTime'])
        if uptime:
            try:
                metrics['uptime'] = int(uptime) // 100  # Convert timeticks to seconds
            except:
                pass
        
        # Interface statistics
        interface_stats = self.collect_interface_stats()
        if interface_stats:
            metrics.update(interface_stats)
        
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
            # Get all interface statistics
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
    
    def collect(self) -> Dict[str, Any]:
        """Main collection method"""
        logger.info(f"Collecting from SNMP device: {self.ip}")
        
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
                result['metrics'] = [metrics]
            
            logger.info(f"Successfully collected data from {self.ip}")
            
        except Exception as e:
            logger.error(f"Error collecting from {self.ip}: {e}")
            result['logs'].append({
                'level': 'error',
                'source': self.ip,
                'message': f"Collection error: {str(e)}",
                'category': 'collector'
            })
        
        return result

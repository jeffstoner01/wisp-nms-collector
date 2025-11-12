"""
Network Scanner Module
Discovers SNMP-enabled devices on specified subnets
"""

import logging
import ipaddress
import subprocess
import asyncio
from typing import List, Dict, Any, Set, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path

# pysnmp 7.x imports
from pysnmp.hlapi.v3arch.asyncio import *

logger = logging.getLogger(__name__)


class NetworkScanner:
    """Network scanner for discovering SNMP devices"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize network scanner"""
        self.config = config
        self.discovery_config = config.get('discovery', {})
        self.subnets = self.discovery_config.get('subnets', [])
        self.community = self.discovery_config.get('snmp_community', 'public')
        self.discovery_threads = self.discovery_config.get('discovery_threads', 50)
        
        # Cache file for discovered devices
        self.cache_file = Path('discovered_devices.json')
        self.discovered_devices: Set[str] = self.load_cache()
        
    def load_cache(self) -> Set[str]:
        """Load previously discovered device IPs from cache"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    logger.info(f"Loaded {len(data)} devices from cache")
                    return set(data)
            except Exception as e:
                logger.error(f"Error loading cache: {e}")
        return set()
    
    def save_cache(self):
        """Save discovered device IPs to cache"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(list(self.discovered_devices), f)
            logger.info(f"Saved {len(self.discovered_devices)} devices to cache")
        except Exception as e:
            logger.error(f"Error saving cache: {e}")
    
    def ping_host(self, ip: str, timeout: int = 1) -> bool:
        """
        Fast ICMP ping to check if host is alive
        Returns True if host responds to ping
        """
        try:
            # Use system ping command for speed
            # -c 1: send 1 packet
            # -W timeout: wait timeout seconds
            # -q: quiet output
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(timeout), '-q', ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout + 1
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, Exception):
            return False
    
    async def snmp_check_async(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Check if IP responds to SNMP and get device info
        Returns device info dict if SNMP responds, None otherwise
        """
        try:
            # Query sysDescr OID to identify device
            errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
                SnmpEngine(),
                CommunityData(self.community),
                await UdpTransportTarget.create((ip, 161), timeout=2, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # sysDescr
            )
            
            if errorIndication or errorStatus:
                return None
            
            # Device responded to SNMP!
            sys_descr = str(varBinds[0][1])
            
            # Get sysName
            errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
                SnmpEngine(),
                CommunityData(self.community),
                await UdpTransportTarget.create((ip, 161), timeout=2, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0'))  # sysName
            )
            
            sys_name = str(varBinds[0][1]) if not errorIndication and not errorStatus else ip
            
            # Identify vendor from sysDescr
            vendor = self.identify_vendor(sys_descr)
            device_type = self.identify_device_type(sys_descr, vendor)
            
            device_info = {
                'ip': ip,
                'name': sys_name,
                'vendor': vendor,
                'deviceType': device_type,
                'sysDescr': sys_descr,
                'deviceId': f"{vendor}-{ip.replace('.', '-')}"
            }
            
            logger.info(f"✅ Discovered {vendor} device at {ip}: {sys_name}")
            return device_info
            
        except Exception as e:
            logger.debug(f"SNMP check failed for {ip}: {e}")
            return None
    
    def identify_vendor(self, sys_descr: str) -> str:
        """Identify device vendor from sysDescr"""
        sys_descr_lower = sys_descr.lower()
        
        if 'mikrotik' in sys_descr_lower or 'routeros' in sys_descr_lower:
            return 'mikrotik'
        elif 'ubiquiti' in sys_descr_lower or 'airmax' in sys_descr_lower or 'airfiber' in sys_descr_lower:
            return 'ubiquiti'
        elif 'cisco' in sys_descr_lower:
            return 'cisco'
        elif 'juniper' in sys_descr_lower:
            return 'juniper'
        elif 'linux' in sys_descr_lower:
            return 'linux'
        else:
            return 'generic'
    
    def identify_device_type(self, sys_descr: str, vendor: str) -> str:
        """Identify device type from sysDescr"""
        sys_descr_lower = sys_descr.lower()
        
        if vendor == 'mikrotik':
            if 'ccr' in sys_descr_lower or 'rb' in sys_descr_lower:
                return 'router'
            elif 'crs' in sys_descr_lower or 'css' in sys_descr_lower:
                return 'switch'
            else:
                return 'router'
        elif vendor == 'ubiquiti':
            if 'rocket' in sys_descr_lower or 'powerbeam' in sys_descr_lower or 'nanobeam' in sys_descr_lower:
                return 'ap'
            elif 'nanostation' in sys_descr_lower or 'litebeam' in sys_descr_lower:
                return 'cpe'
            elif 'airfiber' in sys_descr_lower:
                return 'backhaul'
            else:
                return 'ap'
        else:
            return 'other'
    
    def scan_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Scan a single IP address
        Returns device info if SNMP device found, None otherwise
        """
        # Skip if already discovered (unless doing full re-scan)
        if ip in self.discovered_devices:
            return None
        
        # First, quick ping check
        if not self.ping_host(ip):
            return None
        
        # Host is alive, try SNMP
        device_info = asyncio.run(self.snmp_check_async(ip))
        
        if device_info:
            self.discovered_devices.add(ip)
            return device_info
        
        return None
    
    def scan_subnet(self, subnet: str) -> List[Dict[str, Any]]:
        """
        Scan an entire subnet for SNMP devices
        Returns list of discovered devices
        """
        logger.info(f"🔍 Starting scan of subnet: {subnet}")
        
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            total_ips = network.num_addresses
            
            logger.info(f"Subnet {subnet} contains {total_ips:,} IP addresses")
            
            # Generate list of IPs to scan
            # Skip network and broadcast addresses for /24 and smaller
            if network.prefixlen >= 24:
                ips_to_scan = [str(ip) for ip in network.hosts()]
            else:
                # For larger networks, scan all IPs
                ips_to_scan = [str(ip) for ip in network]
            
            logger.info(f"Scanning {len(ips_to_scan):,} IPs with {self.discovery_threads} threads...")
            
            discovered = []
            scanned_count = 0
            
            # Parallel scanning
            with ThreadPoolExecutor(max_workers=self.discovery_threads) as executor:
                futures = {executor.submit(self.scan_ip, ip): ip for ip in ips_to_scan}
                
                for future in as_completed(futures):
                    scanned_count += 1
                    
                    # Progress logging every 1000 IPs
                    if scanned_count % 1000 == 0:
                        progress = (scanned_count / len(ips_to_scan)) * 100
                        logger.info(f"Progress: {scanned_count:,}/{len(ips_to_scan):,} ({progress:.1f}%) - Found {len(discovered)} devices")
                    
                    try:
                        device_info = future.result()
                        if device_info:
                            discovered.append(device_info)
                    except Exception as e:
                        logger.error(f"Error scanning {futures[future]}: {e}")
            
            logger.info(f"✅ Subnet scan complete: {subnet} - Found {len(discovered)} devices")
            return discovered
            
        except Exception as e:
            logger.error(f"Error scanning subnet {subnet}: {e}")
            return []
    
    def discover_devices(self) -> List[Dict[str, Any]]:
        """
        Main discovery method - scans all configured subnets
        Returns list of all discovered devices
        """
        if not self.subnets:
            logger.warning("No subnets configured for discovery")
            return []
        
        logger.info(f"🚀 Starting network discovery for {len(self.subnets)} subnet(s)")
        
        all_devices = []
        
        for subnet in self.subnets:
            devices = self.scan_subnet(subnet)
            all_devices.extend(devices)
        
        # Save cache
        self.save_cache()
        
        logger.info(f"🎉 Discovery complete! Found {len(all_devices)} total devices")
        return all_devices
    
    def quick_rescan_known_devices(self, known_ips: List[str]) -> List[Dict[str, Any]]:
        """
        Quick re-scan of known device IPs to check if they're still online
        Much faster than full subnet scan
        """
        logger.info(f"🔄 Quick re-scan of {len(known_ips)} known devices")
        
        devices = []
        
        with ThreadPoolExecutor(max_workers=self.discovery_threads) as executor:
            futures = {executor.submit(self.scan_ip, ip): ip for ip in known_ips}
            
            for future in as_completed(futures):
                try:
                    device_info = future.result()
                    if device_info:
                        devices.append(device_info)
                except Exception as e:
                    logger.error(f"Error re-scanning {futures[future]}: {e}")
        
        logger.info(f"✅ Re-scan complete: {len(devices)}/{len(known_ips)} devices online")
        return devices


if __name__ == "__main__":
    # Test scanner
    import yaml
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Test with a small subnet
    test_config = {
        'discovery': {
            'subnets': ['10.0.0.0/24'],  # Small test range
            'snmp_community': 'BlueRidgeNet',
            'discovery_threads': 50
        }
    }
    
    scanner = NetworkScanner(test_config)
    devices = scanner.discover_devices()
    
    print(f"\n{'='*60}")
    print(f"Discovered {len(devices)} devices:")
    print(f"{'='*60}")
    for device in devices:
        print(f"  {device['ip']:15} - {device['vendor']:12} - {device['name']}")

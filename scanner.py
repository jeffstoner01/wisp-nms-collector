"""
Network scanner for SNMP device discovery using CLI tools
"""

import ipaddress
import logging
import subprocess
import re
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class NetworkScanner:
    def __init__(self, community: str = "public", threads: int = 50, cache_file: str = "device_cache.json"):
        self.community = community
        self.threads = threads
        self.discovered_devices = []
        self.cache_file = cache_file
        self.cache = self.load_cache()
    
    def scan_subnets(self, subnets: List[str]) -> List[Dict]:
        """
        Scan multiple subnets for SNMP devices
        
        Args:
            subnets: List of CIDR subnet strings (e.g., ["10.0.0.0/24"])
        
        Returns:
            List of discovered device dictionaries
        """
        logger.info(f"🚀 Starting network discovery for {len(subnets)} subnet(s)")
        
        all_devices = []
        
        for subnet in subnets:
            devices = self.scan_subnet(subnet)
            all_devices.extend(devices)
        
        logger.info(f"✅ Discovery complete! Found {len(all_devices)} total devices")
        return all_devices
    
    def scan_subnet(self, subnet_str: str) -> List[Dict]:
        """
        Scan a single subnet for SNMP devices
        
        Args:
            subnet_str: CIDR subnet string (e.g., "10.0.0.0/24")
        
        Returns:
            List of discovered device dictionaries
        """
        logger.info(f"🔍 Starting scan of subnet: {subnet_str}")
        
        try:
            subnet = ipaddress.ip_network(subnet_str, strict=False)
        except ValueError as e:
            logger.error(f"Invalid subnet: {subnet_str} - {e}")
            return []
        
        # Get all IPs in subnet (excluding network and broadcast)
        all_ips = [str(ip) for ip in subnet.hosts()]
        total_ips = len(all_ips)
        
        logger.info(f"Subnet {subnet_str} contains {total_ips:,} IP addresses")
        
        # First, ping sweep to find live hosts
        logger.info(f"🔍 Ping sweep to find live hosts...")
        live_ips = self.ping_sweep(all_ips)
        logger.info(f"✅ Found {len(live_ips)} responding hosts")
        
        # Then SNMP check on live hosts
        logger.info(f"Scanning {len(live_ips):,} IPs with {self.threads} threads...")
        devices = self.snmp_scan(live_ips)
        
        logger.info(f"✅ Subnet scan complete: {subnet_str} - Found {len(devices)} devices")
        return devices
    
    def ping_sweep(self, ips: List[str]) -> List[str]:
        """
        Ping sweep to find live hosts
        
        Args:
            ips: List of IP addresses to ping
        
        Returns:
            List of IPs that responded to ping
        """
        live_ips = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_ip = {executor.submit(self.ping_ip, ip): ip for ip in ips}
            
            completed = 0
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    if future.result():
                        live_ips.append(ip)
                except Exception as e:
                    logger.debug(f"Ping error for {ip}: {e}")
                
                completed += 1
                if completed % 1000 == 0:
                    logger.info(f"Ping progress: {completed:,}/{len(ips):,} ({100*completed/len(ips):.1f}%) - Found {len(live_ips)} live hosts")
        
        return live_ips
    
    def ping_ip(self, ip: str) -> bool:
        """
        Ping a single IP address
        
        Args:
            ip: IP address to ping
        
        Returns:
            True if ping successful, False otherwise
        """
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def snmp_scan(self, ips: List[str]) -> List[Dict]:
        """
        SNMP scan on list of IPs
        
        Args:
            ips: List of IP addresses to check
        
        Returns:
            List of discovered device dictionaries
        """
        devices = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_ip = {executor.submit(self.check_snmp, ip): ip for ip in ips}
            
            completed = 0
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    device = future.result()
                    if device:
                        devices.append(device)
                except Exception as e:
                    logger.debug(f"SNMP scan error for {ip}: {e}")
                
                completed += 1
                if completed % 100 == 0:
                    logger.info(f"SNMP progress: {completed:,}/{len(ips):,} - Found {len(devices)} devices")
        
        return devices
    
    def check_snmp(self, ip: str) -> Optional[Dict]:
        """
        Check if IP responds to SNMP and get device info
        Tries SNMPv2c first, falls back to SNMPv1 if needed
        
        Args:
            ip: IP address to check
        
        Returns:
            Device info dict if SNMP responds, None otherwise
        """
        # Try SNMPv2c first
        result = self._snmp_get(ip, '1.3.6.1.2.1.1.1.0', version='2c')
        if not result:
            # Fall back to SNMPv1
            result = self._snmp_get(ip, '1.3.6.1.2.1.1.1.0', version='1')
        
        if not result:
            return None
        
        sys_descr = result
        
        # Get sysName
        sys_name_result = self._snmp_get(ip, '1.3.6.1.2.1.1.5.0', version='2c')
        if not sys_name_result:
            sys_name_result = self._snmp_get(ip, '1.3.6.1.2.1.1.5.0', version='1')
        
        sys_name = sys_name_result if sys_name_result else ip
        
        # Identify vendor from sysDescr
        vendor = self.identify_vendor(sys_descr)
        device_type = self.identify_device_type(sys_descr, vendor)
        
        device_info = {
            'ip': ip,
            'name': sys_name,
            'vendor': vendor,
            'deviceType': device_type,
            'sysDescr': sys_descr,
            'deviceId': f"{vendor}-{ip.replace('.', '-')}",
            'status': 'online'
        }
        
        logger.info(f"✅ Discovered {vendor} device at {ip}: {sys_name}")
        return device_info
    
    def _snmp_get(self, ip: str, oid: str, version: str = '2c') -> Optional[str]:
        """
        Execute snmpget command to retrieve a single OID value
        
        Args:
            ip: IP address to query
            oid: SNMP OID to retrieve
            version: SNMP version ('1' or '2c')
        
        Returns:
            OID value as string, or None if failed
        """
        try:
            cmd = [
                'snmpget',
                '-v', version,
                '-c', self.community,
                '-t', '3',  # 3 second timeout
                '-r', '2',  # 2 retries
                '-Oqv',     # Output: quick, value only
                ip,
                oid
            ]
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=10,
                text=True
            )
            
            if result.returncode == 0 and result.stdout.strip():
                # Clean up the output
                value = result.stdout.strip()
                # Remove quotes if present
                value = value.strip('"').strip("'")
                return value
            
            return None
            
        except Exception as e:
            logger.debug(f"SNMP get failed for {ip} OID {oid}: {e}")
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
        elif 'cambium' in sys_descr_lower:
            return 'cambium'
        elif 'linux' in sys_descr_lower:
            # Check if it's a Ubiquiti device running Linux
            if 'armv7l' in sys_descr_lower or 'mips' in sys_descr_lower:
                return 'ubiquiti'
            return 'linux'
        else:
            return 'generic'
    
    def identify_device_type(self, sys_descr: str, vendor: str) -> str:
        """Identify device type from sysDescr"""
        sys_descr_lower = sys_descr.lower()
        
        # Check for specific device types
        if 'router' in sys_descr_lower or 'ccr' in sys_descr_lower or 'rb' in sys_descr_lower:
            return 'router'
        elif 'switch' in sys_descr_lower or 'crs' in sys_descr_lower:
            return 'switch'
        elif 'ap' in sys_descr_lower or 'access point' in sys_descr_lower or 'rocket' in sys_descr_lower or 'nanostation' in sys_descr_lower:
            return 'ap'
        elif 'cpe' in sys_descr_lower or 'litebeam' in sys_descr_lower or 'powerbeam' in sys_descr_lower:
            return 'cpe'
        elif 'airfiber' in sys_descr_lower or 'ptp' in sys_descr_lower:
            return 'backhaul'
        else:
            # Default based on vendor
            if vendor == 'mikrotik':
                return 'router'
            elif vendor == 'ubiquiti':
                return 'ap'
            else:
                return 'unknown'

    def load_cache(self) -> Dict:
        """Load device cache from file"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    cache = json.load(f)
                logger.info(f"📦 Loaded {len(cache.get('devices', []))} devices from cache")
                return cache
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}")
        return {'devices': [], 'last_full_scan': 0}
    
    def save_cache(self, devices: List[Dict]):
        """Save discovered devices to cache"""
        try:
            cache_data = {
                'devices': devices,
                'last_full_scan': time.time()
            }
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            logger.info(f"💾 Saved {len(devices)} devices to cache")
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")
    
    def get_cached_ips(self) -> List[str]:
        """Get list of IPs from cache"""
        return [device['ip'] for device in self.cache.get('devices', [])]
    
    def should_do_full_scan(self, force_interval: int = 3600) -> bool:
        """
        Determine if a full scan should be performed
        
        Args:
            force_interval: Seconds between full scans (default 1 hour)
        
        Returns:
            True if full scan should be done
        """
        last_scan = self.cache.get('last_full_scan', 0)
        time_since_scan = time.time() - last_scan
        
        # Do full scan if:
        # 1. Never scanned before (last_scan == 0)
        # 2. Enough time has passed since last full scan
        if last_scan == 0:
            logger.info("🔍 No previous scan found, performing full scan")
            return True
        elif time_since_scan >= force_interval:
            logger.info(f"🔍 {int(time_since_scan)}s since last full scan, performing full scan")
            return True
        else:
            logger.info(f"⚡ Using cached devices ({int(force_interval - time_since_scan)}s until next full scan)")
            return False
    
    def quick_scan_cached_devices(self) -> List[Dict]:
        """
        Quickly scan only cached devices without full subnet scan
        
        Returns:
            List of discovered devices
        """
        cached_ips = self.get_cached_ips()
        
        if not cached_ips:
            logger.warning("No cached devices found, returning empty list")
            return []
        
        logger.info(f"⚡ Quick scanning {len(cached_ips)} cached devices...")
        devices = self.snmp_scan(cached_ips)
        logger.info(f"✅ Quick scan complete: {len(devices)} devices responded")
        
        return devices

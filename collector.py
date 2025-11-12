#!/usr/bin/env python3
"""
WISP NMS Collector Agent
Collects SNMP data from network devices and sends to NMS API
"""

import os
import sys
import time
import json
import logging
import requests
from datetime import datetime
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml
from scanner import NetworkScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('collector.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class NMSCollector:
    """Main collector agent class"""
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize the collector with configuration"""
        self.config = self.load_config(config_path)
        self.api_url = self.config['nms']['url'].rstrip('/')
        self.api_key = self.config['nms']['api_key']
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
        })
        
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {config_path}")
            return config
        except FileNotFoundError:
            logger.error(f"Configuration file {config_path} not found")
            sys.exit(1)
        except yaml.YAMLError as e:
            logger.error(f"Error parsing configuration: {e}")
            sys.exit(1)
    
    def send_heartbeat(self) -> bool:
        """Send heartbeat to NMS"""
        try:
            response = self.session.post(
                f"{self.api_url}/api/trpc/collector.heartbeat",
                json={
                    "apiKey": self.api_key,
                    "version": "1.0.0",
                    "ipAddress": self.get_local_ip()
                },
                timeout=10
            )
            response.raise_for_status()
            result = response.json()
            logger.info(f"Heartbeat sent successfully: {result}")
            return True
        except Exception as e:
            logger.error(f"Failed to send heartbeat: {e}")
            return False
    
    def get_local_ip(self) -> str:
        """Get local IP address"""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "unknown"
    
    def submit_devices(self, devices: List[Dict[str, Any]]) -> bool:
        """Submit device data to NMS"""
        if not devices:
            return True
            
        try:
            response = self.session.post(
                f"{self.api_url}/api/trpc/collector.submitDevices",
                json={
                    "apiKey": self.api_key,
                    "devices": devices
                },
                timeout=30
            )
            response.raise_for_status()
            result = response.json()
            logger.info(f"Submitted {len(devices)} devices successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to submit devices: {e}")
            return False
    
    def submit_metrics(self, metrics: List[Dict[str, Any]]) -> bool:
        """Submit device metrics to NMS"""
        if not metrics:
            return True
            
        try:
            response = self.session.post(
                f"{self.api_url}/api/trpc/collector.submitMetrics",
                json={
                    "apiKey": self.api_key,
                    "metrics": metrics
                },
                timeout=30
            )
            response.raise_for_status()
            result = response.json()
            logger.info(f"Submitted {len(metrics)} metrics successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to submit metrics: {e}")
            return False
    
    def submit_snmp_data(self, snmp_data: List[Dict[str, Any]]) -> bool:
        """Submit SNMP data to NMS"""
        if not snmp_data:
            return True
            
        try:
            response = self.session.post(
                f"{self.api_url}/api/trpc/collector.submitSnmpData",
                json={
                    "apiKey": self.api_key,
                    "data": snmp_data
                },
                timeout=30
            )
            response.raise_for_status()
            result = response.json()
            logger.info(f"Submitted {len(snmp_data)} SNMP records successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to submit SNMP data: {e}")
            return False
    
    def submit_logs(self, logs: List[Dict[str, Any]]) -> bool:
        """Submit logs to NMS"""
        if not logs:
            return True
            
        try:
            response = self.session.post(
                f"{self.api_url}/api/trpc/collector.submitLogs",
                json={
                    "apiKey": self.api_key,
                    "logs": logs
                },
                timeout=30
            )
            response.raise_for_status()
            result = response.json()
            logger.info(f"Submitted {len(logs)} log entries successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to submit logs: {e}")
            return False
    
    def collect_from_device(self, device_config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Collect data from a single device"""
        device_ip = device_config['ip']
        device_type = device_config.get('type', 'router')
        
        logger.info(f"Collecting data from {device_ip} ({device_type})")
        
        try:
            # Import device-specific collectors
            if device_config.get('vendor') == 'mikrotik':
                from collectors.mikrotik import MikroTikCollector
                collector = MikroTikCollector(device_config)
            elif device_config.get('vendor') == 'ubiquiti':
                from collectors.ubiquiti import UbiquitiCollector
                collector = UbiquitiCollector(device_config)
            else:
                from collectors.snmp import SNMPCollector
                collector = SNMPCollector(device_config)
            
            return collector.collect()
            
        except Exception as e:
            logger.error(f"Error collecting from {device_ip}: {e}")
            return None
    
    def run_collection_cycle(self):
        """Run a single collection cycle for all devices"""
        logger.info("Starting collection cycle")
        
        devices = self.config.get('devices', [])
        if not devices:
            logger.warning("No devices configured")
            return
        
        all_devices = []
        all_metrics = []
        all_snmp_data = []
        all_logs = []
        
        # Collect from all devices in parallel
        max_workers = self.config.get('collector', {}).get('max_workers', 10)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_device = {
                executor.submit(self.collect_from_device, device): device
                for device in devices
            }
            
            for future in as_completed(future_to_device):
                device_config = future_to_device[future]
                try:
                    result = future.result()
                    if result:
                        if 'device' in result:
                            all_devices.append(result['device'])
                        if 'metrics' in result:
                            all_metrics.extend(result['metrics'])
                        if 'snmp_data' in result:
                            all_snmp_data.extend(result['snmp_data'])
                        if 'logs' in result:
                            all_logs.extend(result['logs'])
                except Exception as e:
                    logger.error(f"Error processing {device_config['ip']}: {e}")
        
        # Submit all collected data
        self.submit_devices(all_devices)
        self.submit_metrics(all_metrics)
        self.submit_snmp_data(all_snmp_data)
        self.submit_logs(all_logs)
        
        logger.info("Collection cycle completed")
    
    def run_discovery(self):
        """Run network discovery to find devices"""
        discovery_config = self.config.get('discovery', {})
        
        if not discovery_config.get('enabled', False):
            logger.info("Network discovery is disabled")
            return []
        
        logger.info("🔍 Starting network discovery...")
        scanner = NetworkScanner(self.config)
        discovered_devices = scanner.discover_devices()
        
        if discovered_devices:
            logger.info(f"Discovered {len(discovered_devices)} devices, submitting to NMS...")
            # Convert discovered devices to device format
            devices = []
            for dev in discovered_devices:
                devices.append({
                    'deviceId': dev['deviceId'],
                    'name': dev['name'],
                    'ip': dev['ip'],
                    'vendor': dev['vendor'],
                    'deviceType': dev['deviceType'],
                    'status': 'online',
                    'firmwareVersion': dev.get('sysDescr', '')
                })
            
            self.submit_devices(devices)
        
        return discovered_devices
    
    def run(self):
        """Run the collector agent"""
        logger.info("Starting WISP NMS Collector Agent")
        logger.info(f"NMS URL: {self.api_url}")
        
        # Send initial heartbeat
        self.send_heartbeat()
        
        # Run initial discovery if enabled
        discovered = self.run_discovery()
        
        # Get settings
        interval = self.config.get('collector', {}).get('interval', 60)
        discovery_config = self.config.get('discovery', {})
        scan_interval = discovery_config.get('scan_interval', 3600)
        last_discovery = time.time()
        
        logger.info(f"Collection interval: {interval} seconds")
        if discovery_config.get('enabled', False):
            logger.info(f"Discovery scan interval: {scan_interval} seconds")
        
        # Main collection loop
        while True:
            try:
                self.run_collection_cycle()
                
                # Send heartbeat every cycle
                self.send_heartbeat()
                
                # Check if it's time for another discovery scan
                if discovery_config.get('enabled', False):
                    if time.time() - last_discovery >= scan_interval:
                        logger.info("Running periodic network discovery...")
                        self.run_discovery()
                        last_discovery = time.time()
                
                # Wait for next cycle
                time.sleep(interval)
                
            except KeyboardInterrupt:
                logger.info("Collector agent stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(10)  # Wait before retrying

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='WISP NMS Collector Agent')
    parser.add_argument(
        '-c', '--config',
        default='config.yaml',
        help='Path to configuration file (default: config.yaml)'
    )
    parser.add_argument(
        '--test',
        action='store_true',
        help='Run a single collection cycle and exit'
    )
    
    args = parser.parse_args()
    
    collector = NMSCollector(args.config)
    
    if args.test:
        logger.info("Running in test mode (single cycle)")
        collector.send_heartbeat()
        collector.run_collection_cycle()
        logger.info("Test completed")
    else:
        collector.run()


if __name__ == '__main__':
    main()

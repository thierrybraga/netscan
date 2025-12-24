import threading
import time
import logging
import asyncio
import ipaddress
from typing import Dict, List, Optional
from .models import DeviceInfo
from .scanner import (
    scan_and_update_devices_ping_only, 
    comprehensive_network_scan, 
    get_gateway_ip, 
    get_network_info, 
    get_arp_table_devices
)

logger = logging.getLogger(__name__)

# Global State
device_data_lock = threading.Lock()
_global_device_data: Dict[str, DeviceInfo] = {}
_initial_scan_in_progress = False
_initial_scan_completed = False
_monitor_mode_active = False
_monitor_thread: Optional[threading.Thread] = None

def get_global_device_data() -> Dict[str, DeviceInfo]:
    with device_data_lock:
        return _global_device_data.copy()

def get_device_data_lock():
    return device_data_lock

def is_initial_scan_in_progress():
    return _initial_scan_in_progress

def is_initial_scan_completed():
    return _initial_scan_completed

def is_monitor_mode_active():
    return _monitor_mode_active

def set_monitor_mode_active(active: bool):
    global _monitor_mode_active
    _monitor_mode_active = active

def set_monitor_thread(thread: Optional[threading.Thread]):
    global _monitor_thread
    _monitor_thread = thread

def get_monitor_thread():
    return _monitor_thread

def run_async_in_thread(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def run_initial_full_scan_in_background(ping_workers: int, nmap_workers: int, cidr_target: Optional[str]):
    global _initial_scan_in_progress, _initial_scan_completed, _global_device_data
    start_time = time.time()
    with device_data_lock:
        _initial_scan_in_progress = True

    try:
        # 1. Obter gateway e subrede
        gateway_ip = run_async_in_thread(get_gateway_ip())
        my_ip, netmask = run_async_in_thread(get_network_info())
        network = None
        if cidr_target:
            try:
                network = ipaddress.ip_network(cidr_target, strict=False)
            except ValueError:
                logger.error(f"CIDR alvo inválido: {cidr_target}")
                network = None
        if network is None and my_ip and netmask:
            try:
                network = ipaddress.ip_network(f"{my_ip}/{netmask}", strict=False)
            except ValueError as e:
                logger.error(f"Falha ao construir rede a partir de IP/máscara: {e}")
                network = None

        # 2. Scan de ping em toda a subrede
        if network:
            ip_list = [str(ip) for ip in network.hosts()]
            devices = run_async_in_thread(
                scan_and_update_devices_ping_only({ip: DeviceInfo(ip=ip, status='unknown') for ip in ip_list},
                                                  ping_workers))
            with device_data_lock:
                _global_device_data.update(devices)

        # 3. Consultar tabela ARP
        arp_devices = run_async_in_thread(get_arp_table_devices())
        with device_data_lock:
            for ip, dev in arp_devices.items():
                if ip not in _global_device_data:
                    _global_device_data[ip] = dev
                else:
                    _global_device_data[ip].mac = dev.mac if dev.mac != 'N/A' else _global_device_data[ip].mac
                    _global_device_data[ip].vendor = dev.vendor if dev.vendor != 'N/A' else _global_device_data[
                        ip].vendor

        # 4. Scan Nmap/SNMP para dispositivos ativos
        active_devices = [d for d in _global_device_data.values() if d.status == "up"]
        if active_devices:
            detailed_devices = run_async_in_thread(
                comprehensive_network_scan(ping_workers, nmap_workers, active_devices))
            with device_data_lock:
                _global_device_data.update({d.ip: d for d in detailed_devices})

        elapsed_time = time.time() - start_time
        logger.info(
            f"Scan inicial concluído em {elapsed_time:.2f}s. {len(_global_device_data)} dispositivos encontrados.")
    except Exception as e:
        logger.error(f"Erro no scan inicial: {e}")
    finally:
        with device_data_lock:
            _initial_scan_in_progress = False
            _initial_scan_completed = True


def monitor_network_in_background(ping_workers: int, nmap_workers: int, interval_ms: int, cidr_target: Optional[str]):
    global _monitor_mode_active, _global_device_data
    last_full_scan = time.time()
    FULL_SCAN_INTERVAL = 6 * 3600  # 6 horas

    while _monitor_mode_active:
        try:
            with device_data_lock:
                devices = _global_device_data.copy()
            if not devices:
                arp_devices = run_async_in_thread(get_arp_table_devices())
                with device_data_lock:
                    for ip, dev in arp_devices.items():
                        devices[ip] = dev
                if not devices and cidr_target:
                    try:
                        network = ipaddress.ip_network(cidr_target, strict=False)
                        ip_list = [str(ip) for ip in network.hosts()]
                        devices.update({ip: DeviceInfo(ip=ip, status='unknown') for ip in ip_list})
                    except ValueError:
                        logger.error(f"CIDR alvo inválido durante monitoramento: {cidr_target}")
            updated_devices = run_async_in_thread(scan_and_update_devices_ping_only(devices, ping_workers))
            with device_data_lock:
                _global_device_data.update(updated_devices)

            if time.time() - last_full_scan > FULL_SCAN_INTERVAL:
                active_devices = [d for d in _global_device_data.values() if d.status == "up"]
                if active_devices:
                    detailed_devices = run_async_in_thread(comprehensive_network_scan(1, nmap_workers, active_devices))
                    with device_data_lock:
                        _global_device_data.update({d.ip: d for d in detailed_devices})
                last_full_scan = time.time()
                logger.info("Scan Nmap/SNMP periódico concluído.")
        except Exception as e:
            logger.error(f"Erro no monitoramento: {e}")
        time.sleep(interval_ms / 1000)

    logger.info("Monitoramento parado.")

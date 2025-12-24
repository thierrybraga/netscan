import dash
from dash.dependencies import Input, Output, State
import threading
import time
import ipaddress
import logging
from typing import List

from ..core.services import (
    run_async_in_thread,
    get_gateway_ip,
    get_network_info,
    run_initial_full_scan_in_background,
    monitor_network_in_background,
    get_device_data_lock,
    get_global_device_data,
    is_initial_scan_in_progress,
    is_initial_scan_completed,
    is_monitor_mode_active,
    set_monitor_mode_active,
    get_monitor_thread,
    set_monitor_thread
)
from .components import (
    create_network_graph,
    create_device_details_table,
    create_network_info_panel
)

logger = logging.getLogger(__name__)

def register_callbacks(app):
    @app.callback(
        [
            Output("network-graph", "figure"),
            Output("scan-status", "children"),
            Output("interval-component", "disabled"),
            Output("interval-component", "interval"),
            Output("device-details-table", "children"),
            Output("loading-message", "children"),
            Output("network-info-panel", "children")
        ],
        [
            Input("full-scan-button", "n_clicks"),
            Input("monitor-button", "n_clicks"),
            Input("stop-monitor-button", "n_clicks"),
            Input("interval-component", "n_intervals"),
            Input("monitor-interval-input", "value"),
            Input("cidr-input", "value"),
            Input("status-filter", "value"),
            Input("search-input", "value")
        ],
        [
            State("ping-workers-input", "value"),
            State("nmap-workers-input", "value")
        ],
        prevent_initial_call=False
    )
    def update_dashboard(full_clicks, monitor_clicks, stop_clicks, n_intervals, monitor_interval,
                         cidr_target, status_filter, search_query,
                         ping_workers, nmap_workers):
        
        ctx = dash.callback_context
        triggered_id = ctx.triggered[0]["prop_id"].split(".")[0] if ctx.triggered else "initial_load"

        status_message = ""
        interval_disabled = True
        loading_message = ""
        current_interval_ms = monitor_interval * 1000

        gateway_ip = run_async_in_thread(get_gateway_ip())
        my_ip, netmask = run_async_in_thread(get_network_info())

        # Calcular num_hosts de forma segura
        num_hosts_possible = 0
        try:
            if my_ip and netmask:
                network = ipaddress.ip_network(f"{my_ip}/{netmask}", strict=False)
                num_hosts_possible = network.num_addresses - 2  # Exclui endereço de rede e broadcast
        except ValueError as e:
            logger.error(f"Erro ao calcular o número de hosts: {e}. my_ip: {my_ip}, netmask: {netmask}")
            num_hosts_possible = 0

        # Access global state via services getters/setters
        _initial_scan_in_progress = is_initial_scan_in_progress()
        _initial_scan_completed = is_initial_scan_completed()
        _monitor_mode_active = is_monitor_mode_active()
        _monitor_thread = get_monitor_thread()
        _global_device_data = get_global_device_data()
        device_data_lock = get_device_data_lock()

        try:
            if triggered_id == "initial_load":
                status_message = "Iniciando scan inicial..." if _initial_scan_in_progress else \
                    f"Scan inicial concluído. Topologia gerada com {len(_global_device_data)} dispositivos." if _initial_scan_completed else \
                        "Aguardando scan inicial..."
                loading_message = status_message
                interval_disabled = not _monitor_mode_active

            elif triggered_id == "full-scan-button":
                if _monitor_mode_active:
                    set_monitor_mode_active(False)
                    if _monitor_thread and _monitor_thread.is_alive():
                        _monitor_thread.join(timeout=2)
                    set_monitor_thread(None)
                
                threading.Thread(target=run_initial_full_scan_in_background, args=(ping_workers, nmap_workers, cidr_target)).start()
                status_message = "Scan completo iniciado."
                loading_message = "Executando scan completo..."
                interval_disabled = True

            elif triggered_id == "monitor-button":
                if not _monitor_mode_active:
                    set_monitor_mode_active(True)
                    t = threading.Thread(target=monitor_network_in_background,
                                                       args=(ping_workers, nmap_workers, current_interval_ms, cidr_target))
                    t.daemon = True
                    t.start()
                    set_monitor_thread(t)
                    status_message = "Monitoramento iniciado."
                    loading_message = f"Monitorando a cada {monitor_interval}s..."
                    interval_disabled = False
                else:
                    status_message = "Monitoramento já ativo."
                    loading_message = f"Monitorando a cada {monitor_interval}s..."
                    interval_disabled = False

            elif triggered_id == "stop-monitor-button":
                if _monitor_mode_active:
                    set_monitor_mode_active(False)
                    if _monitor_thread and _monitor_thread.is_alive():
                        _monitor_thread.join(timeout=2)
                    set_monitor_thread(None)
                    status_message = f"Monitoramento parado às {time.strftime('%H:%M:%S')}."
                    loading_message = "Monitoramento parado."
                    interval_disabled = True
                else:
                    status_message = "Monitoramento já inativo."
                    loading_message = "Monitoramento inativo."

            elif triggered_id == "interval-component" and _monitor_mode_active:
                status_message = f"Atualização de monitoramento às {time.strftime('%H:%M:%S')}."
                loading_message = f"Monitorando a cada {monitor_interval}s..."
                interval_disabled = False

            elif triggered_id == "monitor-interval-input":
                status_message = f"Intervalo atualizado para {monitor_interval}s."
                if _monitor_mode_active:
                    set_monitor_mode_active(False)
                    if _monitor_thread and _monitor_thread.is_alive():
                        _monitor_thread.join(timeout=2)
                    
                    set_monitor_mode_active(True)
                    t = threading.Thread(target=monitor_network_in_background,
                                                       args=(ping_workers, nmap_workers, current_interval_ms, cidr_target))
                    t.daemon = True
                    t.start()
                    set_monitor_thread(t)
                    loading_message = f"Monitoramento reiniciado com intervalo de {monitor_interval}s..."
                else:
                    loading_message = "Pronto para escanear ou monitorar."
                interval_disabled = not is_monitor_mode_active()

            # Lógica de filtragem dos dispositivos
            # Re-fetch global data as it might have been updated by threads
            with device_data_lock:
                all_devices = list(get_global_device_data().values())

            filtered_devices = all_devices

            if search_query:
                filtered_devices = [d for d in filtered_devices if search_query.lower() in d.ip.lower() or (
                            d.hostname and search_query.lower() in d.hostname.lower())]

            if status_filter != "all":
                filtered_devices = [d for d in filtered_devices if d.status == status_filter]

            devices_to_display = filtered_devices

        except Exception as e:
            logger.error(f"Erro no callback: {e}")
            status_message = f"Erro: {e}"
            loading_message = f"Erro: {e}"
            interval_disabled = True
            devices_to_display = []
            all_devices = []

        return (
            create_network_graph(devices_to_display, gateway_ip, my_ip),
            status_message,
            interval_disabled,
            current_interval_ms,
            create_device_details_table(devices_to_display),
            loading_message,
            create_network_info_panel(gateway_ip, netmask, num_hosts_possible, len(all_devices), len(devices_to_display))
        )

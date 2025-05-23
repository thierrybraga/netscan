import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State
import plotly.graph_objects as go
import networkx as nx
import ipaddress
import asyncio
import time
import logging
from typing import List, Dict, Optional
import threading
from netscan import DeviceInfo, comprehensive_network_scan, get_gateway_ip, get_network_info, \
    scan_and_update_devices_ping_only, get_arp_table_devices

# Configuração de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Estado global
device_data_lock = threading.Lock()
_global_device_data: Dict[str, DeviceInfo] = {}
_initial_scan_in_progress = False
_initial_scan_completed = False
_monitor_mode_active = False
_monitor_thread: Optional[threading.Thread] = None
DEFAULT_REFRESH_INTERVAL_MS = 30000  # 30 segundos


# --- Funções Auxiliares para o Layout ---
def create_header():
    return html.H1(
        "Dashboard de Monitoramento de Rede",
        style={
            "textAlign": "center",
            "color": "#2c3e50",
            "padding": "20px",
            "backgroundColor": "#a7d9ee",
            "borderRadius": "10px",
            "boxShadow": "0 4px 8px rgba(0,0,0,0.1)",
        }
    )


def create_network_info_panel(gateway_ip: Optional[str], netmask: Optional[str], num_hosts_possible: int,
                              num_devices_total: int, num_devices_filtered: int):
    return html.Div([
        html.H3("Informações da Rede", style={"color": "#34495e"}),
        html.P(f"Gateway: {gateway_ip or 'N/A'}"),
        html.P(f"Máscara: {netmask or 'N/A'}"),
        html.P(f"Hosts Possíveis: {num_hosts_possible if netmask else 'N/A'}"),
        html.P(f"Dispositivos Descobertos (Total): {num_devices_total}"),
        html.P(f"Dispositivos Exibidos (Filtrados): {num_devices_filtered}", style={"fontWeight": "bold"}),
    ], style={
        "padding": "15px",
        "backgroundColor": "#ffffff",
        "borderRadius": "10px",
        "boxShadow": "0 4px 8px rgba(0,0,0,0.1)",
        "marginBottom": "20px"
    })


def create_controls_panel():
    return html.Div([
        html.H3("Controles", style={"textAlign": "center", "color": "#34495e"}),
        html.Label("Intervalo de Monitoramento (segundos):",
                   title="Define o intervalo entre pings no modo de monitoramento"),
        dcc.Input(id="monitor-interval-input", type="number", value=30, min=10, max=300, step=5),
        html.Label("Pings Paralelos:", title="Número de pings simultâneos para maior eficiência"),
        dcc.Input(id="ping-workers-input", type="number", value=50, min=1, max=100, step=1),
        html.Label("Nmap Paralelos:", title="Número de scans Nmap simultâneos"),
        dcc.Input(id="nmap-workers-input", type="number", value=10, min=1, max=50, step=1),
        html.Button("Scan Completo", id="full-scan-button", n_clicks=0, style={"width": "100%", "marginTop": "10px"}),
        html.Button("Monitorar", id="monitor-button", n_clicks=0, style={"width": "100%", "marginTop": "10px"}),
        html.Button("Parar Monitoramento", id="stop-monitor-button", n_clicks=0,
                    style={"width": "100%", "marginTop": "10px"}),
        html.Label("Filtrar por Status:", title="Filtrar dispositivos por status (ativo/inativo)"),
        dcc.Dropdown(
            id="status-filter",
            options=[
                {"label": "Todos", "value": "all"},
                {"label": "Ativos", "value": "up"},
                {"label": "Inativos", "value": "down"}
            ],
            value="all",
            style={"marginTop": "10px"}
        ),
        html.Label("Buscar Dispositivo:", title="Buscar por IP ou hostname"),
        dcc.Input(id="search-input", type="text", placeholder="IP ou Hostname",
                  style={"width": "100%", "marginTop": "10px"}),
        html.Div(id="scan-status", style={"marginTop": "15px", "textAlign": "center"}),
        dcc.Loading(id="loading-status", children=html.P(id="loading-message", style={"color": "#007bff"})),
    ], style={
        "flex": "1",
        "minWidth": "300px",
        "maxWidth": "400px",
        "padding": "20px",
        "backgroundColor": "#ffffff",
        "borderRadius": "10px",
        "boxShadow": "0 4px 8px rgba(0,0,0,0.1)"
    })


def create_topology_panel():
    return html.Div([
        html.H3("Topologia da Rede", style={"textAlign": "center", "color": "#34495e"}),
        dcc.Graph(id="network-graph", style={"height": "600px"}, config={'displayModeBar': True, 'scrollZoom': True}),
    ], style={
        "flex": "3",
        "minWidth": "500px",
        "padding": "20px",
        "backgroundColor": "#ffffff",
        "borderRadius": "10px",
        "boxShadow": "0 4px 8px rgba(0,0,0,0.1)"
    })


def create_details_table_panel():
    return html.Div([
        html.H3("Detalhes dos Dispositivos", style={"textAlign": "center", "color": "#34495e"}),
        dcc.Loading(id="loading-table", children=html.Div(id="device-details-table")),
    ], style={
        "padding": "20px",
        "backgroundColor": "#ffffff",
        "borderRadius": "10px",
        "boxShadow": "0 4px 8px rgba(0,0,0,0.1)",
        "marginTop": "20px"
    })


# --- Geração do Grafo ---
try:
    from networkx.drawing.nx_agraph import graphviz_layout

    _HAS_GRAPHVIZ = True
except (ImportError, ModuleNotFoundError):
    _HAS_GRAPHVIZ = False


def create_network_graph(devices: List[DeviceInfo], gateway_ip: Optional[str], my_ip: Optional[str]) -> go.Figure:
    if not devices:
        return go.Figure(layout=go.Layout(
            title="Nenhum dispositivo encontrado",
            annotations=[
                dict(text="Aguardando scan ou nenhum dispositivo ativo/filtrado", x=0.5, y=0.5, showarrow=False,
                     font=dict(size=20))]
        ))

    G = nx.DiGraph()
    node_colors, node_labels, node_sizes, node_symbols = {}, {}, {}, {}

    # Adicionar nós
    for dev in devices:
        G.add_node(dev.ip)
        label = dev.hostname if dev.hostname not in ("N/A", "localhost", "") else dev.ip
        node_labels[dev.ip] = label
        # Definir cores, símbolos e tamanhos com base no status e tipo de dispositivo
        if dev.status == "up":
            if dev.ip == gateway_ip:
                node_colors[dev.ip], node_symbols[dev.ip], node_sizes[
                    dev.ip] = "#e74c3c", "diamond", 40  # Vermelho para Gateway
            elif dev.ip == my_ip:
                node_colors[dev.ip], node_symbols[dev.ip], node_sizes[
                    dev.ip] = "#f39c12", "square", 35  # Laranja para Máquina Local
            else:
                node_colors[dev.ip], node_symbols[dev.ip], node_sizes[
                    dev.ip] = "#2ecc71", "circle", 30  # Verde para Host Ativo
        else:
            node_colors[dev.ip], node_symbols[dev.ip], node_sizes[
                dev.ip] = "#95a5a6", "circle", 25  # Cinza para Host Inativo (menor)

    # Adicionar arestas (estrela com gateway no centro, ou a máquina local se não houver gateway)
    effective_root_ip = gateway_ip or my_ip
    if effective_root_ip and effective_root_ip not in G.nodes():
        # Se o gateway/minha IP não estiver na lista filtrada de dispositivos,
        # vamos escolher o primeiro dispositivo ativo como raiz se não houver gateway/my_ip na lista,
        # ou o primeiro dispositivo se não houver ativos.
        if devices:
            effective_root_ip = next((d.ip for d in devices if d.status == "up"), devices[0].ip)
        else:
            effective_root_ip = None  # Não há dispositivos para formar grafo

    if effective_root_ip:
        for dev in devices:
            if dev.ip != effective_root_ip:
                G.add_edge(effective_root_ip, dev.ip)

    # Layout do grafo
    pos = {}
    if G.nodes():  # Só tenta o layout se houver nós
        try:
            if _HAS_GRAPHVIZ:
                # Usar um grafo temporário sem direção para o layout para evitar problemas com layout direcional inicial
                temp_G = nx.Graph()
                temp_G.add_nodes_from(G.nodes())
                temp_G.add_edges_from(G.edges())
                pos = graphviz_layout(temp_G, prog="dot")
                # Ajustar a posição para centralizar o root na parte superior (ou um local coerente)
                if effective_root_ip and effective_root_ip in pos:
                    root_x, root_y = pos[effective_root_ip]
                    # Encontrar a posição mais alta (Y máximo) para alinhar o gateway/root
                    max_y = max(p[1] for p in pos.values())
                    pos = {n: (x, y + (max_y - root_y)) for n, (x, y) in pos.items()}

            else:
                # Fallback para spring_layout se Graphviz não estiver disponível
                raise ImportError
        except (ImportError, ModuleNotFoundError):
            logger.warning("Graphviz indisponível ou erro no layout. Usando spring layout como fallback.")
            # Ajuste o `k` (distância ideal entre os nós) e `iterations` para melhor dispersão
            fixed_pos = {effective_root_ip: (0, 0)} if effective_root_ip else None
            pos = nx.spring_layout(G, k=1.0 / (len(G.nodes()) ** 0.5) * 5, iterations=50, pos=fixed_pos)
            # Se a posição inicial for fixada, pode ser necessário um ajuste manual posterior se o gráfico não ficar bom.

    else:  # Caso não haja nós para o layout
        pos = {}  # Grafo vazio, sem posições

    edge_x, edge_y = [], []
    for src, dst in G.edges():
        x0, y0 = pos[src]
        x1, y1 = pos[dst]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y, mode="lines", line=dict(width=1.5, color="#888"),
        hoverinfo="none", showlegend=False  # Não mostrar na legenda
    )

    node_x, node_y, hover_texts, colors, sizes, symbols = [], [], [], [], [], []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        dev = next((d for d in devices if d.ip == node), None)
        if dev:
            hover_texts.append(
                f"<b>{dev.ip}</b><br>Status: {dev.status.upper()}<br>Hostname: {dev.hostname}<br>"
                f"MAC: {dev.mac}<br>Vendor: {dev.vendor}<br>OS: {dev.os}<br>"
                f"Portas Abertas: {', '.join(dev.open_ports) if dev.open_ports else 'N/A'}<br>"
                f"Serviços: {', '.join(dev.services) if dev.services else 'N/A'}<br>"
                f"Latência: {f'{dev.response_time:.2f} ms' if dev.response_time > 0 else 'N/A'}<br>"
                f"Jitter: {f'{dev.jitter:.2f} ms' if dev.jitter > 0 else 'N/A'}<br>"
                f"Última Vez Visto: {dev.last_seen}<br>SNMP SysDescr: {dev.snmp_info.get('sysDescr', 'N/A')}<br>"
                f"SNMP SysName: {dev.snmp_info.get('sysName', 'N/A')}"
            )
        colors.append(node_colors.get(node, "#95a5a6"))
        sizes.append(node_sizes.get(node, 30))
        symbols.append(node_symbols.get(node, "circle"))

    node_trace = go.Scatter(
        x=node_x, y=node_y, mode="markers+text", text=[node_labels[n] for n in G.nodes],
        textposition="bottom center", hoverinfo="text", textfont=dict(size=10, color="#34495e"),
        marker=dict(size=sizes, color=colors, symbol=symbols, line=dict(color="black", width=1.5)),
        name="Dispositivos",  # Nome genérico para não aparecer na legenda principal
        showlegend=False
    )

    # Legenda customizada para melhor clareza
    legend_traces = [
        go.Scatter(x=[None], y=[None], mode="markers",
                   marker=dict(size=15, color="#e74c3c", symbol="diamond", line=dict(color="black", width=1.5)),
                   name="Gateway"),
        go.Scatter(x=[None], y=[None], mode="markers",
                   marker=dict(size=15, color="#f39c12", symbol="square", line=dict(color="black", width=1.5)),
                   name="Máquina Local"),
        go.Scatter(x=[None], y=[None], mode="markers",
                   marker=dict(size=15, color="#2ecc71", symbol="circle", line=dict(color="black", width=1.5)),
                   name="Host Ativo"),
        go.Scatter(x=[None], y=[None], mode="markers",
                   marker=dict(size=15, color="#95a5a6", symbol="circle", line=dict(color="black", width=1.5)),
                   name="Host Inativo")
    ]

    fig = go.Figure(data=[edge_trace, node_trace] + legend_traces, layout=go.Layout(
        title="Topologia da Rede", title_x=0.5, showlegend=True, hovermode="closest",
        margin=dict(b=20, l=5, r=5, t=40), plot_bgcolor="#e6f7ff",
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            bgcolor="rgba(255,255,255,0.8)",
            bordercolor="LightSteelBlue",
            borderwidth=1
        ),
    ))
    return fig


# --- Tabela de Detalhes ---
# Esta função não precisa mais da lógica de filtragem, pois receberá dados já filtrados
def create_device_details_table(devices: List[DeviceInfo]) -> dash_table.DataTable:
    sorted_devices = sorted(devices, key=lambda d: (d.status != 'up', ipaddress.ip_address(d.ip)))
    data = [
        {
            "IP": d.ip, "Hostname": d.hostname, "MAC": d.mac, "Vendor": d.vendor, "Status": d.status.upper(),
            "Device Type": d.device_type.capitalize(), "OS": d.os, "Open Ports": ", ".join(d.open_ports) or "N/A",
            "Services": ", ".join(d.services) or "N/A",
            "Latency (ms)": f"{d.response_time:.2f}" if d.response_time > 0 else "N/A",
            "Jitter (ms)": f"{d.jitter:.2f}" if d.jitter > 0 else "N/A", "Last Seen": d.last_seen,
            "First Seen": d.first_seen,
            "Vulnerabilities": len(d.vulnerabilities) if d.vulnerabilities else 0,
            "SNMP SysDescr": d.snmp_info.get('sysDescr', 'N/A'),
            "SNMP SysName": d.snmp_info.get('sysName', 'N/A'),
            "SNMP SysLocation": d.snmp_info.get('sysLocation', 'N/A'),
            "SNMP Uptime": d.snmp_info.get('sysUpTime', 'N/A')
        } for d in sorted_devices
    ]

    columns = [{"name": k, "id": k} for k in [
        "IP", "Hostname", "Status", "Device Type", "MAC", "Vendor", "OS", "Open Ports", "Services",
        "Latency (ms)", "Jitter (ms)", "Last Seen", "First Seen", "Vulnerabilities",
        "SNMP SysDescr", "SNMP SysName", "SNMP SysLocation", "SNMP Uptime"
    ]]
    return dash_table.DataTable(
        id="device-table", data=data, columns=columns,
        style_header={"backgroundColor": "#2c3e50", "color": "white", "fontWeight": "bold", "textAlign": "center"},
        style_cell={"textAlign": "left", "padding": "10px", "fontSize": "14px"},
        style_data_conditional=[
            {"if": {"row_index": "odd"}, "backgroundColor": "#f8f9fa"},
            {"if": {"column_id": "Status", "filter_query": "{Status} eq 'UP'"}, "color": "green", "fontWeight": "bold"},
            {"if": {"column_id": "Status", "filter_query": "{Status} eq 'DOWN'"}, "color": "red", "fontWeight": "bold"},
            {"if": {"column_id": "Status", "filter_query": "{Status} eq 'UNKNOWN'"}, "color": "orange"}
        ],
        filter_action="native", sort_action="native", page_action="native", page_size=10, export_format="xlsx",
        style_table={"overflowX": "auto"}
    )


# --- Lógica de Escaneamento ---
def run_async_in_thread(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def run_initial_full_scan_in_background(ping_workers: int, nmap_workers: int):
    global _initial_scan_in_progress, _initial_scan_completed, _global_device_data
    start_time = time.time()
    with device_data_lock:
        _initial_scan_in_progress = True

    try:
        # 1. Obter gateway e subrede
        gateway_ip = run_async_in_thread(get_gateway_ip())
        my_ip, netmask = run_async_in_thread(get_network_info())
        network = ipaddress.ip_network(f"{my_ip}/{netmask}", strict=False) if my_ip and netmask else None

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


def monitor_network_in_background(ping_workers: int, nmap_workers: int, interval_ms: int):
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


# --- Configuração do App ---
app = dash.Dash(__name__, meta_tags=[{"name": "viewport", "content": "width=device-width, initial-scale=1.0"}])
app.layout = html.Div([
    create_header(),
    dcc.Loading(id="loading-network-info", children=html.Div(id="network-info-panel")),
    html.Div([create_controls_panel(), create_topology_panel()],
             style={"display": "flex", "gap": "20px", "flexWrap": "wrap"}),
    create_details_table_panel(),
    dcc.Interval(id="interval-component", interval=DEFAULT_REFRESH_INTERVAL_MS, n_intervals=0, disabled=True)
], style={"padding": "20px", "backgroundColor": "#f0f2f5"})


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
                     status_filter, search_query,  # Novas variáveis de filtro
                     ping_workers, nmap_workers):
    global _initial_scan_in_progress, _initial_scan_completed, _monitor_mode_active, _monitor_thread
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

    try:
        if triggered_id == "initial_load":
            status_message = "Iniciando scan inicial..." if _initial_scan_in_progress else \
                f"Scan inicial concluído. Topologia gerada com {len(_global_device_data)} dispositivos." if _initial_scan_completed else \
                    "Aguardando scan inicial..."
            loading_message = status_message
            interval_disabled = not _monitor_mode_active

        elif triggered_id == "full-scan-button":
            if _monitor_mode_active:
                _monitor_mode_active = False
                if _monitor_thread and _monitor_thread.is_alive():
                    # Dar um tempo para a thread parar
                    _monitor_thread.join(timeout=2)
                _monitor_thread = None
            threading.Thread(target=run_initial_full_scan_in_background, args=(ping_workers, nmap_workers)).start()
            status_message = "Scan completo iniciado."
            loading_message = "Executando scan completo..."
            interval_disabled = True

        elif triggered_id == "monitor-button":
            if not _monitor_mode_active:
                _monitor_mode_active = True
                _monitor_thread = threading.Thread(target=monitor_network_in_background,
                                                   args=(ping_workers, nmap_workers, current_interval_ms))
                _monitor_thread.daemon = True  # Define como daemon para que a thread termine com o programa principal
                _monitor_thread.start()
                status_message = "Monitoramento iniciado."
                loading_message = f"Monitorando a cada {monitor_interval}s..."
                interval_disabled = False
            else:
                status_message = "Monitoramento já ativo."
                loading_message = f"Monitorando a cada {monitor_interval}s..."

        elif triggered_id == "stop-monitor-button":
            if _monitor_mode_active:
                _monitor_mode_active = False
                if _monitor_thread and _monitor_thread.is_alive():
                    _monitor_thread.join(timeout=2)  # Espera um pouco pela thread terminar
                _monitor_thread = None
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
                # Reinicia a thread de monitoramento com o novo intervalo
                _monitor_mode_active = False
                if _monitor_thread and _monitor_thread.is_alive():
                    _monitor_thread.join(timeout=2)  # Espera a thread atual parar
                _monitor_mode_active = True  # Ativa novamente para o novo thread
                _monitor_thread = threading.Thread(target=monitor_network_in_background,
                                                   args=(ping_workers, nmap_workers, current_interval_ms))
                _monitor_thread.daemon = True
                _monitor_thread.start()
                loading_message = f"Monitoramento reiniciado com intervalo de {monitor_interval}s..."
            else:
                loading_message = "Pronto para escanear ou monitorar."
            interval_disabled = not _monitor_mode_active

        # Lógica de filtragem dos dispositivos
        with device_data_lock:
            all_devices = list(_global_device_data.values())

        filtered_devices = all_devices  # Começa com todos os dispositivos

        # Aplica filtro de busca se houver search_query
        if search_query:
            filtered_devices = [d for d in filtered_devices if search_query.lower() in d.ip.lower() or (
                        d.hostname and search_query.lower() in d.hostname.lower())]

        # Aplica filtro de status se não for "all"
        if status_filter != "all":
            filtered_devices = [d for d in filtered_devices if d.status == status_filter]

        devices_to_display = filtered_devices  # Esta é a lista final para o grafo e tabela

    except Exception as e:
        logger.error(f"Erro no callback: {e}")
        status_message = f"Erro: {e}"
        loading_message = f"Erro: {e}"
        interval_disabled = True

    # Retorna o grafo e a tabela com os dispositivos filtrados
    return (
        create_network_graph(devices_to_display, gateway_ip, my_ip),
        status_message,
        interval_disabled,
        current_interval_ms,
        create_device_details_table(devices_to_display),  # A tabela agora recebe apenas os dispositivos filtrados
        loading_message,
        create_network_info_panel(gateway_ip, netmask, num_hosts_possible, len(all_devices), len(devices_to_display))
    )


if __name__ == "__main__":
    # Inicia o scan inicial em uma thread separada ao iniciar o app
    logger.info("Iniciando scan inicial ao iniciar o aplicativo...")
    threading.Thread(target=run_initial_full_scan_in_background, args=(50, 10)).start()
    app.run(debug=True, port=8050)
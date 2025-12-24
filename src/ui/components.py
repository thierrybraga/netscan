from dash import dcc, html, dash_table
import plotly.graph_objects as go
import networkx as nx
import ipaddress
import logging
from typing import List, Optional
from ..core.models import DeviceInfo
from ..config import DEFAULT_TARGET_CIDR, DEFAULT_PING_WORKERS, DEFAULT_NMAP_WORKERS, DEFAULT_REFRESH_INTERVAL_MS

logger = logging.getLogger(__name__)

try:
    from networkx.drawing.nx_agraph import graphviz_layout
    _HAS_GRAPHVIZ = True
except (ImportError, ModuleNotFoundError):
    _HAS_GRAPHVIZ = False

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
        html.Label("CIDR Alvo:", title="Defina manualmente a subrede a ser escaneada"),
        dcc.Input(id="cidr-input", type="text", value=DEFAULT_TARGET_CIDR, placeholder="Ex: 192.168.1.0/24"),
        html.Label("Intervalo de Monitoramento (segundos):",
                   title="Define o intervalo entre pings no modo de monitoramento"),
        dcc.Input(id="monitor-interval-input", type="number", value=30, min=10, max=300, step=5),
        html.Label("Pings Paralelos:", title="Número de pings simultâneos para maior eficiência"),
        dcc.Input(id="ping-workers-input", type="number", value=DEFAULT_PING_WORKERS, min=1, max=100, step=1),
        html.Label("Nmap Paralelos:", title="Número de scans Nmap simultâneos"),
        dcc.Input(id="nmap-workers-input", type="number", value=DEFAULT_NMAP_WORKERS, min=1, max=50, step=1),
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

    for dev in devices:
        G.add_node(dev.ip)
        label = dev.hostname if dev.hostname not in ("N/A", "localhost", "") else dev.ip
        node_labels[dev.ip] = label
        if dev.status == "up":
            if dev.ip == gateway_ip:
                node_colors[dev.ip], node_symbols[dev.ip], node_sizes[dev.ip] = "#e74c3c", "diamond", 40
            elif dev.ip == my_ip:
                node_colors[dev.ip], node_symbols[dev.ip], node_sizes[dev.ip] = "#f39c12", "square", 35
            else:
                node_colors[dev.ip], node_symbols[dev.ip], node_sizes[dev.ip] = "#2ecc71", "circle", 30
        else:
            node_colors[dev.ip], node_symbols[dev.ip], node_sizes[dev.ip] = "#95a5a6", "circle", 25

    effective_root_ip = gateway_ip or my_ip
    if effective_root_ip and effective_root_ip not in G.nodes():
        if devices:
            effective_root_ip = next((d.ip for d in devices if d.status == "up"), devices[0].ip)
        else:
            effective_root_ip = None

    if effective_root_ip:
        if effective_root_ip not in G.nodes():
             G.add_node(effective_root_ip)
             node_labels[effective_root_ip] = "Gateway/Scanner"
             node_colors[effective_root_ip], node_symbols[effective_root_ip], node_sizes[effective_root_ip] = "#8e44ad", "star", 45

        for dev in devices:
            if dev.ip != effective_root_ip:
                G.add_edge(effective_root_ip, dev.ip)

    pos = {}
    if G.nodes():
        try:
            if _HAS_GRAPHVIZ:
                temp_G = nx.Graph()
                temp_G.add_nodes_from(G.nodes())
                temp_G.add_edges_from(G.edges())
                pos = graphviz_layout(temp_G, prog="dot")
                if effective_root_ip and effective_root_ip in pos:
                    root_x, root_y = pos[effective_root_ip]
                    max_y = max(p[1] for p in pos.values())
                    pos = {n: (x, y + (max_y - root_y)) for n, (x, y) in pos.items()}
            else:
                raise ImportError
        except (ImportError, ModuleNotFoundError):
            logger.warning("Graphviz indisponível ou erro no layout. Usando spring layout como fallback.")
            fixed_pos = {effective_root_ip: (0, 0)} if effective_root_ip else None
            pos = nx.spring_layout(G, k=1.0 / (len(G.nodes()) ** 0.5) * 5, iterations=50, pos=fixed_pos)
    else:
        pos = {}

    edge_x, edge_y = [], []
    for src, dst in G.edges():
        x0, y0 = pos[src]
        x1, y1 = pos[dst]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y, mode="lines", line=dict(width=1.5, color="#888"),
        hoverinfo="none", showlegend=False
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
        name="Dispositivos",
        showlegend=False
    )

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

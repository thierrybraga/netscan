from dash import html, dcc
from ..config import DEFAULT_REFRESH_INTERVAL_MS
from .components import (
    create_header,
    create_controls_panel,
    create_topology_panel,
    create_details_table_panel
)

def create_layout():
    return html.Div([
        create_header(),
        dcc.Loading(id="loading-network-info", children=html.Div(id="network-info-panel")),
        html.Div([create_controls_panel(), create_topology_panel()],
                 style={"display": "flex", "gap": "20px", "flexWrap": "wrap"}),
        create_details_table_panel(),
        dcc.Interval(id="interval-component", interval=DEFAULT_REFRESH_INTERVAL_MS, n_intervals=0, disabled=True)
    ], style={"padding": "20px", "backgroundColor": "#f0f2f5"})

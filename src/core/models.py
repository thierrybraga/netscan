import time
from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class DeviceInfo:
    """
    Estrutura de dados para armazenar informações detalhadas de um dispositivo na rede.
    Cada campo é inicializado com um valor padrão para garantir consistência.
    """
    ip: str
    status: str = 'down'  # 'up', 'down', 'unknown'
    mac: str = 'N/A'
    hostname: str = 'N/A'
    os: str = 'N/A'
    open_ports: List[str] = field(default_factory=list)
    vendor: str = 'N/A'
    snmp_info: Dict[str, Any] = field(default_factory=dict)  # Mais genérico para SNMP
    device_type: str = 'unknown'  # 'gateway', 'local', 'host', 'unknown'
    services: List[str] = field(default_factory=list)  # Serviços descobertos (e.g., via Nmap)
    response_time: float = 0.0  # Latência média do ping
    response_times_history: List[float] = field(default_factory=list)  # Histórico de latências
    jitter: float = 0.0  # Variação da latência (desvio padrão)
    last_seen: str = ''  # Timestamp da última vez que o dispositivo foi visto ativo
    first_seen: str = field(default_factory=lambda: time.strftime(
        '%Y-%m-%d %H:%M:%S'))  # Timestamp da primeira vez que o dispositivo foi descoberto
    vulnerabilities: List[str] = field(default_factory=list)  # Placeholder para futuras detecções de vulnerabilidades

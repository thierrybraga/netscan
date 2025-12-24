import platform
import ipaddress
import shutil
import asyncio
import socket
import time
import re
import statistics
import logging
from typing import Dict, List, Optional, Tuple, Any
import nmap
import netifaces
from mac_vendor_lookup import AsyncMacLookup
from pysnmp.hlapi.asyncio import *
import psutil

from .models import DeviceInfo

# Configuração de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NetworkScanner:
    """
    Gerencia operações de escaneamento de rede, descoberta de dispositivos
    e coleta de informações detalhadas.
    """

    def __init__(self):
        """
        Inicializa o scanner de rede. O `AsyncMacLookup` é inicializado
        apenas quando necessário para evitar sobrecarga.
        """
        self.mac_lookup: Optional[AsyncMacLookup] = None
        self.mac_lookup_initialized: bool = False
        try:
            self.nm = nmap.PortScanner()  # Instância de Nmap PortScanner
        except (nmap.PortScannerError, FileNotFoundError):
            logger.warning("Nmap não encontrado no PATH. Funcionalidades de scan avançado (portas, OS) estarão desabilitadas.")
            self.nm = None

    async def initialize_mac_lookup(self) -> None:
        """
        Inicializa (carrega os dados) a biblioteca AsyncMacLookup de forma assíncrona.
        Isso é feito apenas uma vez para otimizar o desempenho.
        """
        if self.mac_lookup_initialized:
            return

        try:
            self.mac_lookup = AsyncMacLookup()
            # A carga de vendors pode levar um tempo, então aguardamos.
            await self.mac_lookup.load_vendors()
            self.mac_lookup_initialized = True
            logger.info("Dados de MAC vendors carregados com sucesso.")
        except Exception as e:
            logger.warning(f"Não foi possível inicializar MacLookup: {e}. A busca por fabricantes estará indisponível.")
            self.mac_lookup = None
            self.mac_lookup_initialized = False

    async def get_gateway_ip(self) -> Optional[str]:
        """
        Obtém o endereço IP do gateway padrão da rede local.
        Retorna None se não conseguir determinar.
        """
        try:
            gws = netifaces.gateways()
            default_gateway = gws.get('default')
            if default_gateway and netifaces.AF_INET in default_gateway:
                # Retorna o IP do gateway IPv4
                return default_gateway[netifaces.AF_INET][0]
            logger.warning("Não foi possível encontrar o gateway padrão IPv4.")
            return None
        except Exception as e:
            logger.error(f"Erro ao obter o IP do gateway: {e}")
            return None

    async def get_network_info(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Obtém o endereço IP da máquina local e a máscara de rede
        da interface que contém o gateway padrão.
        Retorna (IP, Netmask) ou (None, None) em caso de falha.
        """
        try:
            gateway = await self.get_gateway_ip()
            if not gateway:
                logger.error("Não foi possível determinar o gateway padrão para obter informações de rede.")
                return None, None

            interfaces = netifaces.interfaces()
            for iface in interfaces:
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        for link in addrs[netifaces.AF_INET]:
                            if 'addr' in link and 'netmask' in link:
                                try:
                                    ip_obj = ipaddress.ip_interface(f"{link['addr']}/{link['netmask']}")
                                    # Verifica se o gateway está na mesma subrede da interface
                                    if ipaddress.ip_address(gateway) in ip_obj.network:
                                        logger.info(
                                            f"Rede local detectada: {ip_obj.ip}/{ip_obj.network.netmask} via interface {iface}")
                                        return str(ip_obj.ip), str(ip_obj.network.netmask)
                                except ValueError:
                                    # Ignora IPs inválidos ou máscaras mal formatadas
                                    continue
                except ValueError as e:
                    logger.debug(f"Interface {iface} sem endereços IPv4 válidos: {e}")
                except Exception as e:
                    logger.debug(f"Erro inesperado ao processar interface {iface}: {e}")
                    continue
            logger.warning("Não foi possível encontrar uma interface com o gateway padrão.")
            return None, None
        except Exception as e:
            logger.error(f"Erro geral ao obter informações de rede: {e}")
            return None, None

    async def _ping_device(self, ip: str, timeout: int = 1, count: int = 2) -> Tuple[str, bool, List[float]]:
        """
        Executa pings em um dispositivo e retorna se ele está ativo e os tempos de resposta.
        Melhora a detecção de hosts ativos ao realizar múltiplos pings e analisar a saída.
        O timeout e a contagem foram ajustados para um equilíbrio entre rapidez e confiabilidade.
        """
        response_times = []
        is_alive = False

        if platform.system() == "Windows":
            cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), ip]
            # Regex para Windows: busca por "Tempo=" ou "time=" seguido por milissegundos
            # Pode ser "Tempo<1ms", "Tempo=10ms", "time=10ms"
            pattern = re.compile(r"Tempo[=<]\s*(\d+)ms|time[=<]\s*(\d+)ms", re.IGNORECASE)
        else:  # Linux / macOS
            cmd = ["ping", "-c", str(count), "-W", str(timeout), "-i", "0.2", ip]
            # Regex para Linux/macOS: busca por "time=" seguido por float ou int e "ms"
            pattern = re.compile(r"time=(\d+\.?\d*)\s*ms", re.IGNORECASE)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Adiciona um timeout total para a operação de ping, caso o processo trave
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=(timeout * count) + 2  # Tempo total de ping + buffer
            )

            output = stdout.decode(errors='ignore')

            # Analisa a saída para capturar os tempos de resposta
            for match in pattern.finditer(output):
                try:
                    # O grupo pode ser 1 ou 2 dependendo do regex, pegamos o que não for None
                    time_str = match.group(1) or match.group(2)
                    response_times.append(float(time_str))
                except (ValueError, TypeError):
                    continue

            # Um dispositivo é considerado ativo se houver algum tempo de resposta válido
            if response_times:
                is_alive = True
            elif "Destination Host Unreachable" in output or "Host de destino inacessível" in output:
                is_alive = False  # Explicitamente down
            elif process.returncode != 0:
                is_alive = False  # Ping falhou
            else:
                # Pode haver casos onde o ping é bem-sucedido, mas não há tempo de resposta (e.g., firewall)
                # ou a saída não é parseada. Nesses casos, se o returncode é 0, assumimos UP.
                # No entanto, para detecção de spam e maior precisão, dependemos de tempos de resposta.
                # Se o returncode for 0, mas response_times for vazio, pode indicar algo incomum.
                # Para robustez, mantemos `is_alive` como `bool(response_times)`.
                pass

            return ip, is_alive, response_times
        except asyncio.TimeoutError:
            logger.debug(f"Ping para {ip} excedeu o tempo limite.")
            if process.returncode is None:  # Se o processo ainda estiver rodando
                process.kill()
                await process.wait()
            return ip, False, []
        except Exception as e:
            logger.debug(f"Erro ao pingar {ip}: {e}")
            return ip, False, []

    def calculate_latency_jitter(self, response_times: List[float]) -> Tuple[float, float]:
        """
        Calcula a latência média e o jitter (desvio padrão) de uma lista de tempos de resposta.
        Retorna (latência_media, jitter).
        """
        if not response_times:
            return 0.0, 0.0
        # Convertemos milissegundos para segundos para cálculos mais padrão se necessário,
        # mas mantemos em ms para exibição.
        latency = statistics.mean(response_times)
        jitter = statistics.stdev(response_times) if len(response_times) > 1 else 0.0
        return latency, jitter

    async def _nmap_scan(self, ip: str, arguments: str = "-T4 -F") -> Optional[Dict]:
        """
        Executa um scan Nmap em um dispositivo e retorna informações como portas abertas, OS, etc.
        Usa -F (Fast mode) para scan mais rápido das 100 portas principais.
        """
        if self.nm is None:
            return None

        logger.info(f"Iniciando Nmap scan para {ip}...")
        try:
            # O run_in_executor é crucial para não bloquear o loop de eventos asyncio
            # enquanto o Nmap, que é síncrono, está rodando.
            await asyncio.get_running_loop().run_in_executor(
                None, self.nm.scan, ip, None, arguments
            )

            if ip not in self.nm.all_hosts():
                logger.debug(f"Nmap não encontrou host ativo para {ip} ou scan falhou.")
                return None
            
            logger.info(f"Nmap scan concluído para {ip}.")

            host_info = self.nm[ip]
            result = {
                'ip': ip,
                'hostname': host_info.hostname() or 'N/A',
                'status': host_info.state(),
                'open_ports': [],
                'os': 'N/A',
                'mac': host_info['addresses'].get('mac', 'N/A'),
                'services': []
            }

            # Se o host está ativo e tem portas abertas, coletar informações de portas/serviços
            if host_info.state() == 'up':
                for proto in host_info.all_protocols():
                    lport = host_info[proto].keys()
                    for port in lport:
                        port_info = host_info[proto][port]
                        if port_info['state'] == 'open':
                            result['open_ports'].append(f"{port}/{proto}")
                            service_name = port_info.get('name', 'unknown')
                            product = port_info.get('product', '')
                            version = port_info.get('version', '')
                            extrainfo = port_info.get('extrainfo', '')

                            service_string = f"{service_name}"
                            if product: service_string += f" ({product}"
                            if version: service_string += f" {version}"
                            if extrainfo: service_string += f" {extrainfo}"
                            if product: service_string += ")"

                            result['services'].append(service_string)

                # Detecção de OS aprimorada
                if 'osmatch' in host_info and host_info['osmatch']:
                    # Pega a melhor correspondência de OS (primeira com maior precisão)
                    best_os_match = max(host_info['osmatch'], key=lambda x: float(x.get('accuracy', 0)))
                    result['os'] = best_os_match['name']
                elif 'osclass' in host_info and host_info['osclass']:
                    # Fallback para OS class se osmatch não for detalhado
                    result['os'] = host_info['osclass'][0]['osfamily'] + " " + host_info['osclass'][0]['osgen']

            return result
        except nmap.PortScannerError as e:
            logger.warning(f"Erro Nmap para {ip}: {e}. Verifique se Nmap está instalado e acessível.")
            return None
        except Exception as e:
            logger.debug(f"Erro geral no Nmap para {ip}: {e}")
            return None

    async def _snmp_get(self, ip: str, oid: str, community: str = 'public', timeout: int = 1, retries: int = 1) -> \
    Optional[str]:
        """
        Executa uma requisição SNMP GET para um OID específico.
        Adiciona timeout e retries para robustez.
        """
        try:
            errorIndication, errorStatus, errorIndex, varBinds = await asyncio.wait_for(
                getCmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=1),  # mpModel=1 para SNMP v2c
                    UdpTransportTarget((ip, 161), timeout=timeout, retries=retries),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid))
                ),
                timeout=timeout * retries + 1  # Timeout total para a operação
            )

            if errorIndication or errorStatus:
                # logger.debug(f"SNMP para {ip} OID {oid} falhou: {errorIndication or errorStatus.prettyPrint()}")
                return None

            # Decodifica o valor e remove aspas extras se for um string
            value = str(varBinds[0][1])
            return value.strip('"') if isinstance(value, str) else value
        except asyncio.TimeoutError:
            logger.debug(f"Timeout SNMP para {ip} (OID: {oid})")
            return None
        except Exception as e:
            logger.debug(f"Erro ao executar SNMP para {ip} (OID: {oid}): {e}")
            return None

    async def get_snmp_info(self, ip: str, communities: List[str] = None) -> Dict:
        """
        Coleta informações SNMP de um dispositivo usando várias comunidades.
        Tenta comunidades comuns como 'public' e 'private'.
        """
        if communities is None:
            communities = ['public', 'private']  # Comunidades SNMP comuns

        snmp_data = {'ip': ip}
        oids = {
            'sysDescr': '1.3.6.1.2.1.1.1.0',  # Descrição do sistema
            'sysObjectID': '1.3.6.1.2.1.1.2.0',  # OID do objeto do sistema
            'sysUpTime': '1.3.6.1.2.1.1.3.0',  # Tempo de atividade do sistema
            'sysContact': '1.3.6.1.2.1.1.4.0',  # Contato do sistema
            'sysName': '1.3.6.1.2.1.1.5.0',  # Nome do sistema
            'sysLocation': '1.3.6.1.2.1.1.6.0'  # Localização do sistema
        }

        # Tentar com cada comunidade até obter sucesso ou esgotar
        for community in communities:
            tasks = [self._snmp_get(ip, oid, community) for oid in oids.values()]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            found_any_info = False
            for key, result in zip(oids.keys(), results):
                if not isinstance(result, Exception) and result is not None:
                    snmp_data[key] = result
                    found_any_info = True

            if found_any_info:
                logger.debug(f"Informações SNMP obtidas para {ip} com comunidade '{community}'.")
                break  # Se achou alguma info, para de tentar outras comunidades

        if not snmp_data:  # Se não obteve nenhuma informação
            logger.debug(f"Nenhuma informação SNMP obtida para {ip} com as comunidades testadas.")

        return snmp_data

    async def _parse_arp_output(self, output: str) -> List[Tuple[str, str]]:
        """
        Analisa a saída do comando ARP e extrai pares IP-MAC.
        Refinada para maior robustez e lidar com variações de saída.
        """
        devices = []
        seen_ips = set()
        seen_macs = set()  # Evitar duplicatas por MAC também

        # Padrões para Windows
        if platform.system() == "Windows":
            # Ex: "192.168.1.1    00-11-22-33-44-55     dinâmico"
            pattern = re.compile(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})\s+.*',
                re.IGNORECASE)
            for match in pattern.finditer(output):
                ip = match.group(1)
                mac = match.group(2).replace('-', ':').lower()
                try:
                    # Valida IP
                    ipaddress.ip_address(ip)
                    if ip not in seen_ips and mac not in seen_macs and mac not in (
                    'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'):
                        devices.append((ip, mac))
                        seen_ips.add(ip)
                        seen_macs.add(mac)
                except ValueError:
                    continue
        else:  # Linux / macOS
            lines = output.splitlines()
            for line in lines:
                line = line.strip()
                if not line:
                    continue

                ip, mac = None, None

                # Tentar 'ip neigh show' (moderno, preferível no Linux)
                # Ex: "192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE"
                ip_neigh_match = re.search(
                    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*lladdr\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', line)
                if ip_neigh_match:
                    ip = ip_neigh_match.group(1)
                    mac = ip_neigh_match.group(2).lower()
                else:
                    # Tentar 'arp -a' (legado, mas ainda comum)
                    # Ex: "? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0"
                    # Ex: "192.168.1.1 ether 00:11:22:33:44:55 C eth0"
                    arp_match = re.search(
                        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', line)
                    if arp_match:
                        ip = arp_match.group(1)
                        mac = arp_match.group(2).lower()

                if ip and mac:
                    try:
                        ipaddress.ip_address(ip)  # Valida o IP
                        if ip not in seen_ips and mac not in seen_macs and mac not in (
                        'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'):
                            devices.append((ip, mac))
                            seen_ips.add(ip)
                            seen_macs.add(mac)
                    except ValueError:
                        continue  # IP inválido, ignora

        return devices

    async def get_arp_table_devices(self) -> Dict[str, DeviceInfo]:
        """
        Obtém dispositivos da tabela ARP local do sistema operacional.
        Prioriza 'ip neigh' no Linux e é mais robusto na análise da saída.
        """
        commands = []
        if platform.system() == "Windows":
            commands = [["arp", "-a"]]
        else:  # Linux / macOS
            if shutil.which("ip"):  # Verifica se 'ip' está disponível (moderno)
                commands.append(["ip", "neigh", "show"])
            if shutil.which("arp"):  # Verifica se 'arp' está disponível (legado)
                commands.append(["arp", "-a"])

        device_dict: Dict[str, DeviceInfo] = {}

        for command in commands:
            try:
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=5  # Timeout para o comando ARP
                )

                if process.returncode == 0:
                    parsed_devices = await self._parse_arp_output(stdout.decode(errors='ignore'))

                    if parsed_devices:
                        # Inicializar MAC lookup se necessário
                        if not self.mac_lookup_initialized:
                            await self.initialize_mac_lookup()

                        # Lookup de vendors em paralelo para os MACs obtidos
                        if self.mac_lookup:
                            lookup_tasks = [self._safe_mac_lookup(mac) for ip, mac in parsed_devices]
                            vendors = await asyncio.gather(*lookup_tasks, return_exceptions=True)

                            for i, (ip, mac) in enumerate(parsed_devices):
                                vendor_result = vendors[i]
                                vendor = vendor_result if not isinstance(vendor_result,
                                                                         Exception) and vendor_result is not None else "N/A"

                                # Adiciona ou atualiza DeviceInfo
                                if ip not in device_dict:
                                    device_dict[ip] = DeviceInfo(
                                        ip=ip,
                                        mac=mac,
                                        vendor=vendor,
                                        status='unknown',  # Status inicial até o ping
                                        last_seen=time.strftime('%Y-%m-%d %H:%M:%S'),
                                        first_seen=time.strftime('%Y-%m-%d %H:%M:%S')
                                    )
                                else:  # Atualiza MAC/Vendor se N/A
                                    if device_dict[ip].mac == 'N/A' and mac != 'N/A':
                                        device_dict[ip].mac = mac
                                    if device_dict[ip].vendor == 'N/A' and vendor != 'N/A':
                                        device_dict[ip].vendor = vendor
                        else:  # Se o mac_lookup falhou, apenas preenche o que pode
                            for ip, mac in parsed_devices:
                                if ip not in device_dict:
                                    device_dict[ip] = DeviceInfo(
                                        ip=ip,
                                        mac=mac,
                                        vendor="N/A",
                                        status='unknown',
                                        last_seen=time.strftime('%Y-%m-%d %H:%M:%S'),
                                        first_seen=time.strftime('%Y-%m-%d %H:%M:%S')
                                    )
                                else:
                                    if device_dict[ip].mac == 'N/A' and mac != 'N/A':
                                        device_dict[ip].mac = mac

                        # Retorna a primeira saída bem-sucedida
                        return device_dict

                else:
                    logger.debug(
                        f"Comando ARP {' '.join(command)} falhou com código {process.returncode}: {stderr.decode(errors='ignore').strip()}")

            except asyncio.TimeoutError:
                logger.debug(f"Comando ARP {' '.join(command)} excedeu o tempo limite.")
            except Exception as e:
                logger.debug(f"Erro ao executar comando ARP {' '.join(command)}: {e}")
                continue  # Tenta o próximo comando se houver

        logger.warning("Nenhum comando ARP funcionou para obter dispositivos.")
        return {}

    async def _safe_mac_lookup(self, mac: str) -> str:
        """
        Executa o lookup de MAC vendor de forma segura, com tratamento de exceções.
        """
        if not self.mac_lookup_initialized:
            await self.initialize_mac_lookup()  # Tenta inicializar se ainda não o fez
            if not self.mac_lookup_initialized:  # Se falhou de novo
                return "N/A"

        try:
            return await asyncio.wait_for(self.mac_lookup.lookup(mac), timeout=3)
        except asyncio.TimeoutError:
            logger.debug(f"Timeout ao buscar vendor para MAC {mac}.")
            return "N/A"
        except Exception as e:
            logger.debug(f"Erro ao buscar vendor para MAC {mac}: {e}")
            return "N/A"

    async def scan_network_range(self, network: ipaddress.IPv4Network, ping_workers: int) -> Dict[str, DeviceInfo]:
        """
        Escaneia uma faixa de rede usando ping paralelo para descobrir hosts ativos.
        Otimizado para lidar com redes grandes de forma mais eficiente.
        """
        logger.info(f"Iniciando scan da rede {network} para descoberta de hosts ativos (ping)...")

        hosts = list(network.hosts())
        # Filtra IPs especiais (rede e broadcast) - embora network.hosts() já faça isso
        # Considera também o próprio IP da máquina local.
        my_ip, _ = await self.get_network_info()

        # Otimização: se a rede for muito grande, focar nos primeiros ou usar uma estratégia diferente
        # Para demonstração, manter o limite, mas em produção, uma /16 ou maior exigiria abordagens segmentadas.
        if len(hosts) > 254:  # Ex: limita a uma /24 efetiva se a rede for maior
            logger.warning(
                f"A rede {network} é muito grande ({len(hosts)} hosts). Limitando o ping scan aos primeiros 254 hosts para evitar sobrecarga e timeouts.")
            hosts = hosts[:254]

        semaphore = asyncio.Semaphore(ping_workers)  # Limita o número de pings concorrentes

        async def ping_with_semaphore(ip_str):
            async with semaphore:
                return await self._ping_device(ip_str)

        ping_tasks = [ping_with_semaphore(str(ip)) for ip in hosts]
        results = await asyncio.gather(*ping_tasks, return_exceptions=True)

        devices: Dict[str, DeviceInfo] = {}
        active_count = 0

        for result in results:
            if isinstance(result, Exception):
                continue  # Ignora erros de execução de tarefa

            ip, is_alive, response_times = result
            latency, jitter = self.calculate_latency_jitter(response_times)

            device_info = DeviceInfo(
                ip=ip,
                status='up' if is_alive else 'down',
                response_time=latency,
                jitter=jitter,
                response_times_history=response_times[-10:],  # Armazena os últimos 10 pings
                last_seen=time.strftime('%Y-%m-%d %H:%M:%S'),
                first_seen=time.strftime('%Y-%m-%d %H:%M:%S')
            )
            # Tentar determinar device_type baseado no IP
            gateway_ip = await self.get_gateway_ip()  # Pode ser caro chamar aqui em loop, otimizar
            if ip == my_ip:
                device_info.device_type = 'local'
            elif ip == gateway_ip:
                device_info.device_type = 'gateway'
            elif is_alive:
                device_info.device_type = 'host'

            devices[ip] = device_info
            if is_alive:
                active_count += 1

        logger.info(f"Scan de rede concluído: {active_count}/{len(hosts)} hosts ativos detectados via ping.")
        return devices

    async def scan_and_update_devices_ping_only(self, known_devices: Dict[str, DeviceInfo], ping_workers: int) -> Dict[
        str, DeviceInfo]:
        """
        Escaneia (ping) e atualiza o status de um dicionário de dispositivos conhecidos.
        Também integra informações da tabela ARP para enriquecer dados.
        """
        logger.info(f"Atualizando status de {len(known_devices)} dispositivos via ping...")

        current_devices = known_devices.copy()  # Trabalha em uma cópia para evitar side effects

        # 1. Obter e mesclar informações da tabela ARP
        arp_devices = await self.get_arp_table_devices()
        for ip, arp_dev_info in arp_devices.items():
            if ip not in current_devices:
                current_devices[ip] = arp_dev_info  # Novo dispositivo do ARP
                logger.info(f"Novo dispositivo detectado via ARP: {ip} ({arp_dev_info.mac})")
            else:
                # Atualiza MAC e Vendor se a informação existente for "N/A"
                if current_devices[ip].mac == 'N/A' and arp_dev_info.mac != 'N/A':
                    current_devices[ip].mac = arp_dev_info.mac
                    current_devices[ip].vendor = arp_dev_info.vendor
                elif current_devices[ip].mac != 'N/A' and arp_dev_info.mac != 'N/A' and current_devices[
                    ip].mac != arp_dev_info.mac:
                    logger.warning(
                        f"MAC para {ip} diverge (conhecido: {current_devices[ip].mac}, ARP: {arp_dev_info.mac}). Mantendo o conhecido.")

        # 2. Executar pings em todos os dispositivos conhecidos (incluindo os recém-adicionados do ARP)
        semaphore = asyncio.Semaphore(ping_workers)

        async def ping_with_semaphore(ip_address):
            async with semaphore:
                return await self._ping_device(ip_address)

        ips_to_ping = list(current_devices.keys())
        ping_tasks = [ping_with_semaphore(ip) for ip in ips_to_ping]
        results = await asyncio.gather(*ping_tasks, return_exceptions=True)

        gateway_ip = await self.get_gateway_ip()
        my_ip, _ = await self.get_network_info()

        active_count = 0
        for result in results:
            if isinstance(result, Exception):
                continue

            ip, is_alive, response_times = result
            if ip not in current_devices:  # Deve estar, mas um check extra
                continue

            device = current_devices[ip]
            old_status = device.status

            device.status = 'up' if is_alive else 'down'
            device.last_seen = time.strftime('%Y-%m-%d %H:%M:%S')

            if is_alive:
                latency, jitter = self.calculate_latency_jitter(response_times)
                device.response_time = latency
                device.jitter = jitter
                # Mantém histórico limitado
                device.response_times_history.extend(response_times)
                device.response_times_history = device.response_times_history[-10:]
            else:
                device.response_time = 0.0
                device.jitter = 0.0
                device.response_times_history.clear()  # Limpa histórico se estiver down

            # Determina ou refina o tipo de dispositivo
            if ip == gateway_ip:
                device.device_type = 'gateway'
            elif ip == my_ip:
                device.device_type = 'local'
            elif device.status == 'up':
                device.device_type = 'host'
            else:
                # Se está down, pode ser um host que desligou ou nunca foi visto
                device.device_type = 'unknown' if device.device_type == 'unknown' else device.device_type  # Mantém tipo anterior se já definido

            if old_status != device.status:
                logger.info(f"Status do dispositivo {ip} mudou: {old_status.upper()} -> {device.status.upper()}")

            if device.status == 'up':
                active_count += 1

        logger.info(f"Ping scan de atualização concluído: {active_count}/{len(current_devices)} dispositivos ativos.")
        return current_devices

    async def comprehensive_network_scan(self, nmap_workers: int, snmp_workers: int,
                                         devices_to_scan: List[DeviceInfo]) -> Dict[str, DeviceInfo]:
        """
        Realiza um scan Nmap e SNMP abrangente em uma lista de dispositivos.
        Este scan é mais intensivo e deve ser focado em hosts já identificados como 'up'.
        """
        if not devices_to_scan:
            logger.info("Nenhum dispositivo para scan detalhado.")
            return {}

        logger.info(f"Iniciando scan detalhado (Nmap/SNMP) para {len(devices_to_scan)} dispositivos...")

        # Converte a lista para um dicionário para fácil acesso por IP
        scanned_devices_map: Dict[str, DeviceInfo] = {dev.ip: dev for dev in devices_to_scan}

        # Inicializar MAC lookup no início deste processo se ainda não foi
        if not self.mac_lookup_initialized:
            await self.initialize_mac_lookup()

        # Semáforos para controlar a concorrência
        nmap_semaphore = asyncio.Semaphore(nmap_workers)
        snmp_semaphore = asyncio.Semaphore(snmp_workers)

        async def _run_nmap_for_device(device: DeviceInfo):
            async with nmap_semaphore:
                return await self._nmap_scan(device.ip)

        async def _run_snmp_for_device(device: DeviceInfo):
            async with snmp_semaphore:
                return await self.get_snmp_info(device.ip)

        nmap_tasks = [_run_nmap_for_device(dev) for dev in devices_to_scan]
        snmp_tasks = [_run_snmp_for_device(dev) for dev in devices_to_scan]

        # Executar Nmap e SNMP em paralelo
        # Use return_exceptions=True para que uma falha em uma tarefa não pare todas as outras
        nmap_results = await asyncio.gather(*nmap_tasks, return_exceptions=True)
        snmp_results = await asyncio.gather(*snmp_tasks, return_exceptions=True)

        # Processar resultados do Nmap
        for nmap_res in nmap_results:
            if isinstance(nmap_res, Exception) or nmap_res is None or 'ip' not in nmap_res:
                continue

            ip = nmap_res['ip']
            if ip in scanned_devices_map:
                device = scanned_devices_map[ip]
                device.hostname = nmap_res.get('hostname', device.hostname)
                device.os = nmap_res.get('os', device.os)
                device.open_ports = nmap_res.get('open_ports', device.open_ports)
                device.services = nmap_res.get('services', device.services)

                # Atualizar MAC e Vendor se a informação do Nmap for mais completa
                if nmap_res.get('mac') and nmap_res['mac'] != 'N/A' and device.mac == 'N/A':
                    device.mac = nmap_res['mac']
                    device.vendor = await self._safe_mac_lookup(device.mac)

                # Se Nmap confirmou 'up', atualiza o status se for 'unknown' ou 'down'
                if nmap_res.get('status') == 'up':
                    device.status = 'up'  # Nmap é uma validação forte de UP

        # Processar resultados do SNMP
        for snmp_res in snmp_results:
            if isinstance(snmp_res, Exception) or snmp_res is None or 'ip' not in snmp_res:
                continue

            device_ip = snmp_res.pop('ip')  # Remove 'ip' do dicionário de snmp_data
            if device_ip in scanned_devices_map:
                device = scanned_devices_map[device_ip]
                device.snmp_info = snmp_res  # Armazena todas as informações SNMP

                # Atualizar informações do dispositivo com base no SNMP se estiverem faltando
                if 'sysDescr' in snmp_res and device.os == 'N/A':
                    device.os = snmp_res['sysDescr']
                if 'sysName' in snmp_res and device.hostname == 'N/A':
                    device.hostname = snmp_res['sysName']

                # Se SNMP respondeu, é um forte indicativo que o host está UP
                if device.status != 'up':
                    device.status = 'up'  # Confirma status UP se SNMP respondeu

        logger.info(f"Scan detalhado concluído. Informações atualizadas para {len(scanned_devices_map)} dispositivos.")
        return scanned_devices_map


# Instância global do scanner para ser usada pelas funções de conveniência
scanner = NetworkScanner()


# --- Funções de Conveniência (API Pública) ---
# Estas funções permitem que outras partes do seu código (como o dashboard_app.py)
# interajam com o scanner sem precisar instanciar NetworkScanner diretamente.

async def initialize_scanner():
    """Inicializa o scanner (principalmente o lookup de MAC vendors)."""
    await scanner.initialize_mac_lookup()


async def get_gateway_ip() -> Optional[str]:
    """Retorna o IP do gateway padrão."""
    return await scanner.get_gateway_ip()


async def get_network_info() -> Tuple[Optional[str], Optional[str]]:
    """Retorna o IP local e a máscara de rede."""
    return await scanner.get_network_info()


async def get_arp_table_devices() -> Dict[str, DeviceInfo]:
    """Retorna dispositivos da tabela ARP."""
    return await scanner.get_arp_table_devices()


async def scan_network_range(network: ipaddress.IPv4Network, ping_workers: int) -> Dict[str, DeviceInfo]:
    """Executa um scan de ping em uma faixa de rede."""
    return await scanner.scan_network_range(network, ping_workers)


async def scan_and_update_devices_ping_only(known_devices: Dict[str, DeviceInfo], ping_workers: int) -> Dict[
    str, DeviceInfo]:
    """Atualiza o status de dispositivos conhecidos usando apenas ping."""
    return await scanner.scan_and_update_devices_ping_only(known_devices, ping_workers)


async def comprehensive_network_scan(nmap_workers: int, snmp_workers: int, devices_to_scan: List[DeviceInfo]) -> Dict[
    str, DeviceInfo]:
    """Realiza um scan Nmap e SNMP detalhado em dispositivos."""
    return await scanner.comprehensive_network_scan(nmap_workers, snmp_workers, devices_to_scan)

"""Descoberta de vizinhos IPv6 na rede local.

O equivalente IPv6 do ARP é o NDP (Neighbor Discovery Protocol). A estratégia
aqui é a mesma do módulo IPv4, adaptada às particularidades do IPv6:

1. Solicita respostas enviando ICMPv6 echo ao endereço multicast *all-nodes*
   ``ff02::1`` em cada interface com IPv6 ativo. Todo host IPv6 do enlace
   responde (o RFC 4443 permite ignorar, mas na prática Windows/Linux/Android
   respondem) e o kernel preenche a tabela de vizinhança.
2. Lê a tabela de vizinhança do kernel (``ip -6 neigh``), que mapeia
   endereço IPv6 -> MAC.
3. Acrescenta os endereços IPv6 das interfaces do próprio host, que nunca
   aparecem na tabela de vizinhança.

**Por que só a tabela de vizinhança:** ela contém, por definição, apenas
vizinhos *on-link* (mesmo segmento L2), onde o MAC realmente identifica o
equipamento. Um host IPv6 atrás de um roteador teria o MAC *do roteador* na
tabela — agrupar por MAC nesse caso fundiria hosts remotos dentro do device do
gateway. Por isso nunca inferimos MAC de endereço roteado.

Sem varredura de faixa: um /64 tem 2^64 endereços, então o sweep sequencial que
o IPv4 faz é inviável em IPv6 — a descoberta é inteiramente baseada em NDP.
"""

import ipaddress
import logging
import re
import subprocess
from dataclasses import dataclass

from app.scanner.hosts import is_valid_mac, normalize_mac

logger = logging.getLogger(__name__)

# Endereço multicast "all-nodes" do enlace: todo host IPv6 escuta nele.
ALL_NODES_MULTICAST = "ff02::1"

# Estados da tabela de vizinhança que trazem um MAC confirmado.
# FAILED/INCOMPLETE não têm lladdr confiável e são ignorados.
_VALID_NUD_STATES = ("reachable", "stale", "delay", "probe", "permanent")

# Escopos classificados a partir do endereço.
SCOPE_LINK_LOCAL = "link-local"
SCOPE_ULA = "ula"
SCOPE_GLOBAL = "global"

_IFACE_HEADER_RE = re.compile(r"^\d+:\s+([^:@\s]+)")


# Estados que provam presença RECENTE do vizinho (o kernel confirmou
# alcançabilidade). 'stale' significa apenas "já foi visto um dia" — a entrada
# sobrevive ~30 min após o host sumir, então não serve como prova de que o
# ativo está online agora.
_FRESH_NUD_STATES = frozenset({"REACHABLE", "DELAY", "PROBE"})


@dataclass
class Host6Info:
    """Vizinho IPv6 descoberto (sempre on-link)."""
    ip: str          # endereço IPv6 sem zone id
    mac: str         # MAC normalizado AA:BB:CC:DD:EE:FF
    iface: str = ""  # interface onde o vizinho foi visto
    scope: str = ""  # link-local | ula | global
    state: str = ""  # estado NUD do kernel (REACHABLE, STALE, ...)

    @property
    def is_fresh(self) -> bool:
        """True se o kernel confirmou alcançabilidade recentemente.

        Usado para decidir se a descoberta pode atualizar ``last_seen_at`` do
        device: uma entrada STALE não prova que o host continua na rede.
        """
        return self.state.upper() in _FRESH_NUD_STATES


def ipv6_scope(ip: str) -> str:
    """Classifica um endereço IPv6 em link-local, ULA ou global.

    Returns:
        Um dos SCOPE_*, ou "" se o endereço não for um IPv6 utilizável
        (multicast, loopback, não especificado ou string inválida).
    """
    try:
        addr = ipaddress.ip_address(strip_zone(ip))
    except ValueError:
        return ""
    if addr.version != 6:
        return ""
    if addr.is_multicast or addr.is_loopback or addr.is_unspecified:
        return ""
    if addr.is_link_local:
        return SCOPE_LINK_LOCAL
    # ULA (fc00::/7) — endereçamento privado, equivalente ao RFC1918.
    if addr in ipaddress.ip_network("fc00::/7"):
        return SCOPE_ULA
    return SCOPE_GLOBAL


def strip_zone(ip: str) -> str:
    """Remove o zone id de um endereço link-local ('fe80::1%eth0' -> 'fe80::1')."""
    return (ip or "").split("%", 1)[0].strip()


def is_ipv6(ip: str) -> bool:
    """True se a string for um endereço IPv6 válido (com ou sem zone id)."""
    try:
        return ipaddress.ip_address(strip_zone(ip)).version == 6
    except ValueError:
        return False


def is_routable_ipv6(ip: str) -> bool:
    """True para IPv6 global ou ULA — os endereços que podem ser escaneados.

    Link-local exige zone id (``%iface``) para ser alcançável e depende da
    interface de saída; é catalogado, mas não usado como alvo de scan.
    """
    return ipv6_scope(ip) in (SCOPE_GLOBAL, SCOPE_ULA)


def ipv6_prefix64(ip: str) -> str:
    """Retorna o prefixo /64 de um IPv6 ('2001:db8:1:2::5' -> '2001:db8:1:2::/64').

    Usado para identificar mudança real de rede: endereços temporários de
    privacy extensions (RFC 4941) trocam o sufixo mas mantêm o mesmo /64.
    """
    try:
        net = ipaddress.ip_network(f"{strip_zone(ip)}/64", strict=False)
    except ValueError:
        return ""
    return str(net)


# ---------------------------------------------------------------------------
# Leitura do sistema
# ---------------------------------------------------------------------------

def _iface_macs() -> dict[str, str]:
    """MAC de cada interface, via 'ip link show'. Retorna {iface: mac}.

    Lido separadamente porque 'ip -6 addr show' omite as linhas link/ether.
    No Wi-Fi o MAC pode ser randomizado (``permaddr`` guarda o de fábrica); é o
    MAC *em uso* que interessa, pois é ele que aparece no ARP/NDP dos vizinhos.
    """
    macs: dict[str, str] = {}
    try:
        proc = subprocess.run(
            ["ip", "link", "show"], capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return macs

    current = ""
    for line in proc.stdout.splitlines():
        header = _IFACE_HEADER_RE.match(line)
        if header:
            current = header.group(1)
            continue
        stripped = line.strip()
        if current and stripped.startswith("link/ether"):
            parts = stripped.split()
            if len(parts) >= 2:
                mac = normalize_mac(parts[1])
                if is_valid_mac(mac):
                    macs[current] = mac
    return macs


def _ipv6_interfaces() -> dict[str, str]:
    """Interfaces com IPv6 ativo. Retorna {iface: mac_da_interface}.

    Exclui a loopback. O MAC é usado para atribuir os endereços do próprio host
    ao device correspondente no inventário; interfaces sem MAC (túneis, ppp)
    entram com string vazia — são descobertas, mas não agrupáveis.
    """
    ifaces: dict[str, str] = {}
    try:
        proc = subprocess.run(
            ["ip", "-6", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        logger.debug("'ip -6 addr show' indisponível — IPv6 não será descoberto.")
        return ifaces

    macs = _iface_macs()
    current = ""
    for line in proc.stdout.splitlines():
        header = _IFACE_HEADER_RE.match(line)
        if header:
            current = header.group(1)
            continue
        if current and current != "lo" and line.strip().startswith("inet6 "):
            ifaces.setdefault(current, macs.get(current, ""))
    return ifaces


def _solicit_neighbors(ifaces: list[str], count: int = 2, timeout: int = 2) -> None:
    """Pinga ff02::1 em cada interface para popular a tabela de vizinhança.

    Falhas são ignoradas: o ping multicast retorna código != 0 em várias
    situações normais (nenhuma resposta, host sem IPv6) e o efeito colateral
    desejado — o kernel aprender os vizinhos — acontece mesmo assim.
    """
    for iface in ifaces:
        target = f"{ALL_NODES_MULTICAST}%{iface}"
        for cmd in (["ping", "-6"], ["ping6"]):
            try:
                subprocess.run(
                    cmd + ["-c", str(count), "-W", str(timeout), "-I", iface, target],
                    capture_output=True, timeout=count * timeout + 3,
                )
                break  # comando existe; não tenta a variante seguinte
            except FileNotFoundError:
                continue  # tenta 'ping6' legado
            except (OSError, subprocess.TimeoutExpired):
                break


def read_ipv6_neighbors() -> list[Host6Info]:
    """Lê a tabela de vizinhança IPv6 do kernel ('ip -6 neigh show').

    Formato esperado por linha:
        "fe80::1 dev wlp2s0 lladdr cc:bb:fe:aa:2b:32 router STALE"
    """
    neighbors: list[Host6Info] = []
    args = ["ip", "-6", "neigh", "show"]
    for state in _VALID_NUD_STATES:
        args += ["nud", state]

    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        logger.debug("'ip -6 neigh show' indisponível.")
        return neighbors

    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2 or "lladdr" not in parts:
            continue
        ip = strip_zone(parts[0])
        scope = ipv6_scope(ip)
        if not scope:
            continue  # multicast/loopback/inválido
        lladdr_idx = parts.index("lladdr")
        if lladdr_idx + 1 >= len(parts):
            continue
        mac = normalize_mac(parts[lladdr_idx + 1])
        if not is_valid_mac(mac):
            continue
        iface = parts[parts.index("dev") + 1] if "dev" in parts else ""
        # O estado NUD é o último token em maiúsculas da linha.
        state = next(
            (t for t in reversed(parts) if t.isupper() and t.isalpha()), ""
        )
        neighbors.append(
            Host6Info(ip=ip, mac=mac, iface=iface, scope=scope, state=state)
        )

    return neighbors


def read_local_ipv6_addresses() -> list[Host6Info]:
    """Endereços IPv6 das interfaces do próprio host do monitor.

    O host nunca aparece na própria tabela de vizinhança, então sem isto o
    device que representa o monitor ficaria sem IPv6 no inventário.
    """
    result: list[Host6Info] = []
    ifaces = _ipv6_interfaces()
    if not ifaces:
        return result

    try:
        proc = subprocess.run(
            ["ip", "-6", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return result

    current = ""
    for line in proc.stdout.splitlines():
        header = _IFACE_HEADER_RE.match(line)
        if header:
            current = header.group(1)
            continue
        stripped = line.strip()
        if not stripped.startswith("inet6 ") or current == "lo":
            continue
        mac = ifaces.get(current, "")
        if not is_valid_mac(mac):
            continue  # interface sem MAC (túnel, ppp) — não dá para agrupar
        ip = strip_zone(stripped.split()[1].split("/")[0])
        scope = ipv6_scope(ip)
        if not scope:
            continue
        result.append(Host6Info(
            ip=ip, mac=mac, iface=current, scope=scope, state="REACHABLE",
        ))

    return result


def discover_ipv6_neighbors(solicit: bool = True) -> list[Host6Info]:
    """Descobre todos os vizinhos IPv6 on-link, agrupáveis por MAC.

    Args:
        solicit: se True, pinga ff02::1 antes de ler a tabela para provocar
            respostas de hosts ainda desconhecidos pelo kernel.

    Returns:
        Lista de Host6Info deduplicada por (ip, mac).
    """
    ifaces = _ipv6_interfaces()
    if not ifaces:
        logger.info("Nenhuma interface com IPv6 ativo — descoberta IPv6 ignorada.")
        return []

    if solicit:
        _solicit_neighbors(list(ifaces.keys()))

    found = read_ipv6_neighbors() + read_local_ipv6_addresses()

    deduped: dict[tuple[str, str], Host6Info] = {}
    for host in found:
        deduped.setdefault((host.ip, host.mac), host)

    result = list(deduped.values())
    logger.info(
        "Descoberta IPv6: %d vizinho(s) em %d interface(s) (%s).",
        len(result), len(ifaces), ", ".join(sorted(ifaces)),
    )
    return result


def is_ipv6_available() -> bool:
    """True se o host tem alguma interface (fora a loopback) com IPv6 ativo."""
    return bool(_ipv6_interfaces())


# ---------------------------------------------------------------------------
# Alcançabilidade IPv6
# ---------------------------------------------------------------------------

def zone_of(ip: str) -> str:
    """Interface associada a um endereço IPv6.

    Devolve o zone id explícito ('fe80::1%eth0' -> 'eth0') ou, para link-local
    sem zona, a interface em que o vizinho foi visto. Endereços link-local só
    são alcançáveis com a interface de saída definida — sem ela, ping e connect
    falham com "Invalid argument" e o host pareceria offline.
    """
    if "%" in (ip or ""):
        return ip.split("%", 1)[1]
    target = strip_zone(ip)
    if ipv6_scope(target) != SCOPE_LINK_LOCAL:
        return ""
    for neighbor in read_ipv6_neighbors() + read_local_ipv6_addresses():
        if neighbor.ip == target and neighbor.iface:
            return neighbor.iface
    return ""


def ping6(ip: str, timeout: int = 2, count: int = 1) -> bool:
    """ICMPv6 echo para um endereço IPv6. Usa o 'ping' do sistema (sem root).

    Link-local recebe automaticamente o zone id da interface onde foi visto.
    """
    target = strip_zone(ip)
    zone = zone_of(ip)
    if zone:
        target = f"{target}%{zone}"
    for cmd in (["ping", "-6"], ["ping6"]):
        try:
            proc = subprocess.run(
                cmd + ["-c", str(count), "-W", str(timeout), target],
                capture_output=True, timeout=count * timeout + 3,
            )
            return proc.returncode == 0
        except FileNotFoundError:
            continue  # tenta a variante legado 'ping6'
        except (OSError, subprocess.TimeoutExpired):
            return False
    return False


def _tcp_probe6(
    ip: str, timeout: float = 1.5, probe_ports: tuple[int, ...] = (),
) -> int | None:
    """Conexão TCP sobre IPv6 em portas comuns, em paralelo.

    Espelha ``hosts._tcp_probe``: um RST (connection refused) também prova que
    o host está online, então tanto porta aberta quanto fechada contam.
    """
    import errno as _errno
    import socket as _socket
    from concurrent.futures import ThreadPoolExecutor

    from app.scanner.hosts import _LIVENESS_PROBE_PORTS

    ports = probe_ports or _LIVENESS_PROBE_PORTS
    target = strip_zone(ip)
    # scope_id é obrigatório no connect() de link-local; 0 para global/ULA.
    zone = zone_of(ip)
    try:
        scope_id = _socket.if_nametoindex(zone) if zone else 0
    except (OSError, AttributeError):
        scope_id = 0

    def try_port(port: int) -> int | None:
        try:
            with _socket.socket(_socket.AF_INET6, _socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                err = sock.connect_ex((target, port, 0, scope_id))
                if err == 0 or err == _errno.ECONNREFUSED:
                    return port
        except OSError:
            pass
        return None

    with ThreadPoolExecutor(max_workers=min(len(ports), 32)) as executor:
        for result in executor.map(try_port, ports):
            if result is not None:
                return result
    return None


def is_host_reachable6(ip: str, timeout: int = 2, deep: bool = False) -> tuple[bool, str]:
    """Versão IPv6 de ``hosts.is_host_reachable``.

    Ordem: ICMPv6 → tabela de vizinhança NDP → TCP connect → (deep) TCP amplo.
    Link-local sem zone id não é sondável por TCP; nesse caso só a vizinhança
    responde pela presença do host.

    Returns:
        (is_up, method) — method é "icmp6", "ndp", "tcp6/<porta>" ou "".
    """
    from app.scanner.hosts import _DEEP_PROBE_PORTS

    target = strip_zone(ip)

    if ping6(target, timeout=1):
        return True, "icmp6"

    # Vizinhança NDP — equivalente ao passo "tabela ARP" do IPv4: o ping acima
    # já forçou o kernel a resolver o vizinho.
    for neighbor in read_ipv6_neighbors():
        if neighbor.ip == target and neighbor.is_fresh:
            return True, "ndp"

    if ipv6_scope(target) == SCOPE_LINK_LOCAL and not zone_of(ip):
        # Link-local de interface desconhecida: sem zone id não há como escolher
        # a rota de saída, então não há probe possível.
        return False, ""

    port = _tcp_probe6(ip, timeout=float(timeout))
    if port is not None:
        return True, f"tcp6/{port}"

    if deep:
        port = _tcp_probe6(ip, timeout=float(timeout), probe_ports=_DEEP_PROBE_PORTS)
        if port is not None:
            return True, f"tcp6-deep/{port}"

    return False, ""

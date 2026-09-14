"""Verificação de integridade do DNS da rede.

Sequestro de DNS é um caminho de man-in-the-middle que **não toca em ARP nem em
NDP**: basta que o cliente receba (por DHCP, RA ou por alteração no roteador) o
endereço de um resolvedor controlado pelo atacante. A partir daí todo o tráfego
pode ser desviado sem nenhum conflito de IP para as checagens de
``app/scanner/mitm.py`` perceberem. As duas verificações aqui fecham essa lacuna:

1. **Mudança na lista de resolvedores** — os servidores DNS efetivos do host são
   comparados com um baseline persistido. Um resolvedor novo aparecendo sozinho
   é o sintoma direto de DHCP/RA rogue ou de adulteração do roteador.
2. **Resposta divergente para domínios âncora** — perguntamos a cada resolvedor
   da rede por nomes cujo endereço é público, estável e conhecido de antemão
   (``one.one.one.one`` → 1.1.1.1/1.0.0.1). Se a resposta não bate, o resolvedor
   está reescrevendo respostas.

A consulta é montada na mão sobre UDP/53 (``socket`` da stdlib) para não
introduzir dependência nova e para poder perguntar a um servidor **específico** —
``socket.getaddrinfo`` só consulta o resolvedor do sistema e não serve para
comparar servidores entre si.

Custo: alguns pacotes UDP por execução. Nenhuma varredura.
"""

import ipaddress
import logging
import os
import re
import secrets
import socket
import struct

logger = logging.getLogger(__name__)

# Chave de baseline em AppSetting (por perfil), no mesmo formato usado por
# app/scanner/mitm.py — o botão de redefinir baselines do admin limpa as duas.
KEY_RESOLVERS = "dns.resolvers"

# Domínios cujo endereço é público, estável há anos e verificável sem consultar
# ninguém. São âncoras de referência: se o resolvedor da rede devolve outra
# coisa para eles, ele está reescrevendo respostas.
ANCHOR_DOMAINS: dict[str, frozenset[str]] = {
    "one.one.one.one": frozenset({"1.1.1.1", "1.0.0.1"}),
    "dns.google": frozenset({"8.8.8.8", "8.8.4.4"}),
    "dns.quad9.net": frozenset({"9.9.9.9", "149.112.112.112"}),
}

# Arquivos de resolvedor, em ordem de preferência. Em hosts com
# systemd-resolved o /etc/resolv.conf aponta só para o stub 127.0.0.53 e
# esconde o servidor real da rede — que é justamente o que queremos vigiar.
_RESOLV_FILES = ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf")

_NAMESERVER_RE = re.compile(r"^\s*nameserver\s+(\S+)", re.MULTILINE)

# RCODEs que interessam nomear na mensagem do alerta.
_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


def is_dns_check_enabled(app=None) -> bool:
    """True se a verificação de DNS deve rodar (AppSetting > config)."""
    from flask import current_app

    from app.models import AppSetting

    cfg = app.config if app is not None else current_app.config
    default = bool(cfg.get("DNS_CHECK_ENABLED", True))
    try:
        raw = AppSetting.get_value("dns.check_enabled", "")
    except Exception:
        return default
    if raw == "":
        return default
    return raw in ("1", "true", "True", "on", "yes")


def set_dns_check_enabled(enabled: bool) -> None:
    from app.models import AppSetting

    AppSetting.set_value("dns.check_enabled", "1" if enabled else "0")


# ---------------------------------------------------------------------------
# Resolvedores configurados no host
# ---------------------------------------------------------------------------

def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def read_resolvers() -> list[str]:
    """Servidores DNS efetivos do host, em ordem de configuração.

    Prefere o resolv.conf do systemd-resolved: o ``/etc/resolv.conf`` de um host
    com resolved lista apenas ``127.0.0.53`` (o stub local), que não diz nada
    sobre qual servidor da rede está sendo realmente usado. Só cai para o
    ``/etc/resolv.conf`` quando o primeiro não existe ou não tem nada útil.

    Endereços de loopback são descartados quando existe alguma alternativa —
    perguntar ao stub local mede o upstream de qualquer jeito, mas o baseline
    ficaria cego a uma troca do servidor de verdade.
    """
    found: list[str] = []
    for path in _RESOLV_FILES:
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError as exc:
            logger.debug("Não foi possível ler %s: %s", path, exc)
            continue
        servers = []
        for raw in _NAMESERVER_RE.findall(content):
            try:
                ipaddress.ip_address(raw.split("%")[0])
            except ValueError:
                continue
            if raw not in servers:
                servers.append(raw)
        routable = [s for s in servers if not _is_loopback(s)]
        if routable:
            return routable
        found = found or servers
    return found


# ---------------------------------------------------------------------------
# Consulta DNS mínima (RFC 1035) sobre UDP
# ---------------------------------------------------------------------------

def _encode_name(domain: str) -> bytes:
    out = bytearray()
    for label in domain.strip(".").split("."):
        encoded = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        if not 1 <= len(encoded) <= 63:
            raise ValueError(f"label inválido em {domain!r}")
        out.append(len(encoded))
        out += encoded
    out.append(0)
    return bytes(out)


def _skip_name(data: bytes, offset: int) -> int:
    """Avança o offset para depois de um nome codificado (trata compressão)."""
    while True:
        if offset >= len(data):
            raise ValueError("nome truncado")
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:  # ponteiro de compressão: 2 bytes e acabou
            return offset + 2
        offset += 1 + length


def query_a_record(server: str, domain: str, timeout: float = 3.0) -> dict:
    """Pergunta os registros A de ``domain`` a um servidor DNS específico.

    Returns:
        dict com ``ips`` (lista), ``rcode`` (int ou None) e ``error`` (str).
        Nunca lança: falha de rede vira ``error`` preenchido, porque um
        resolvedor fora do ar não é um achado de segurança.
    """
    result = {"ips": [], "rcode": None, "error": ""}
    qid = secrets.randbelow(65536)
    try:
        question = _encode_name(domain) + struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    except ValueError as exc:
        result["error"] = str(exc)
        return result
    # Flags 0x0100 = recursão desejada.
    packet = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + question

    family = socket.AF_INET6 if ":" in server.split("%")[0] else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        # connect() amarra o socket à origem: respostas de qualquer outro
        # endereço são descartadas pelo kernel.
        sock.connect((server.split("%")[0], 53))
        sock.send(packet)
        data = sock.recv(4096)
    except (OSError, socket.timeout) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    finally:
        sock.close()

    if len(data) < 12:
        result["error"] = "resposta truncada"
        return result
    rid, flags, qdcount, ancount = struct.unpack("!HHHH", data[:8])
    if rid != qid:
        # ID diferente do perguntado: resposta forjada ou fora de ordem.
        result["error"] = "ID da resposta não confere"
        return result
    result["rcode"] = flags & 0x000F

    offset = 12
    try:
        for _ in range(qdcount):
            offset = _skip_name(data, offset) + 4  # QTYPE + QCLASS
        for _ in range(ancount):
            offset = _skip_name(data, offset)
            rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            offset += rdlength
            if rtype == 1 and rdlength == 4:  # A
                result["ips"].append(socket.inet_ntoa(rdata))
    except (ValueError, struct.error) as exc:
        result["error"] = f"resposta malformada: {exc}"
    return result


# ---------------------------------------------------------------------------
# Verificações
# ---------------------------------------------------------------------------

def check_resolver_list(profile) -> dict:
    """Compara a lista de servidores DNS com o baseline e alerta em mudança.

    A primeira execução apenas aprende (a rede é assumida limpa na instalação),
    no mesmo modelo dos baselines de gateway/DHCP.

    Returns: dict com ``current``, ``learned`` (bool) e ``added``/``removed``.
    """
    from app.extensions import db
    from app.models import AlertType, Severity
    from app.scanner.mitm import get_baseline, set_baseline
    from app.scanner.scheduling import emit_alert

    current = read_resolvers()
    out = {"current": current, "learned": False, "added": [], "removed": []}
    if not current:
        logger.debug("Nenhum resolvedor DNS encontrado (profile %d).", profile.id)
        return out

    baseline = get_baseline(KEY_RESOLVERS, profile.id)
    known = baseline.get("servers") or []
    if not known:
        set_baseline(KEY_RESOLVERS, profile.id, {"servers": current})
        db.session.commit()
        out["learned"] = True
        logger.info("Baseline de resolvedores DNS aprendido (%s): %s", profile.name, current)
        return out

    added = [s for s in current if s not in known]
    removed = [s for s in known if s not in current]
    out["added"], out["removed"] = added, removed
    if not added and not removed:
        return out

    # Aceita o novo estado para não repetir o mesmo alerta em todo ciclo.
    set_baseline(KEY_RESOLVERS, profile.id, {"servers": current})

    if added:
        message = (
            f"Servidor DNS novo na configuração da rede: {', '.join(added)} "
            f"(antes: {', '.join(known)}). Um resolvedor injetado por DHCP ou "
            "Router Advertisement não autorizado permite desviar qualquer "
            "conexão sem tocar em ARP/NDP."
        )
        severity, priority = Severity.CRITICAL, True
    else:
        message = (
            f"Servidor DNS removido da configuração da rede: {', '.join(removed)} "
            f"(agora: {', '.join(current)})."
        )
        severity, priority = Severity.WARNING, False

    emit_alert(
        profile.id, None, AlertType.DNS_HIJACK, severity, message,
        match_value=",".join(added or removed), is_priority=priority,
        notify_profile=profile,
    )
    db.session.commit()
    logger.warning("DNS_HIJACK (%s): resolvedores +%s -%s", profile.name, added, removed)
    return out


def check_anchor_domains(profile, servers: list[str], timeout: float = 3.0) -> dict:
    """Resolve os domínios âncora em cada servidor e alerta em divergência.

    Só considera divergência uma resposta **positiva e errada**: erro de rede,
    SERVFAIL e resposta vazia são ruído operacional (servidor ocupado, saída
    UDP/53 bloqueada) e não geram alerta. NXDOMAIN para um domínio âncora, por
    outro lado, é resposta positiva de que o nome não existe — isso é
    reescrita, e conta.

    Returns: dict com ``checked``, ``mismatches`` e ``errors``.
    """
    from app.extensions import db
    from app.models import AlertType, Severity
    from app.scanner.scheduling import emit_alert

    out = {"checked": 0, "mismatches": [], "errors": 0}

    for server in servers:
        for domain, expected in ANCHOR_DOMAINS.items():
            res = query_a_record(server, domain, timeout=timeout)
            if res["error"]:
                out["errors"] += 1
                logger.debug("DNS %s @%s: %s", domain, server, res["error"])
                continue
            out["checked"] += 1
            rcode = res["rcode"]
            ips = set(res["ips"])

            if rcode == 3:  # NXDOMAIN para um domínio que existe
                detail = "respondeu NXDOMAIN"
            elif rcode not in (0, None):
                # SERVFAIL/REFUSED: o servidor não respondeu, não mentiu.
                out["errors"] += 1
                continue
            elif not ips:
                # NOERROR sem registro A: filtro de conteúdo costuma fazer isso,
                # mas também acontece com resolvedor sobrecarregado. Não alerta.
                out["errors"] += 1
                continue
            elif ips & expected:
                continue  # bate com pelo menos um endereço esperado
            else:
                detail = f"respondeu {', '.join(sorted(ips))}"

            out["mismatches"].append((server, domain, detail))
            emit_alert(
                profile.id, None, AlertType.DNS_HIJACK, Severity.CRITICAL,
                (
                    f"DNS {server} devolveu resposta divergente para {domain}: "
                    f"{detail} (esperado {', '.join(sorted(expected))}). "
                    "O resolvedor da rede está reescrevendo respostas — "
                    "qualquer conexão pode estar sendo desviada."
                ),
                match_value=f"{server}/{domain}", is_priority=True,
                notify_profile=profile,
            )
            logger.warning("DNS_HIJACK (%s): %s @%s %s", profile.name, domain, server, detail)

    if out["mismatches"]:
        db.session.commit()
    return out


def check_dns_integrity():
    """Job global: valida os resolvedores DNS da rede em cada perfil ativo.

    A leitura dos resolvedores é do **host do monitor** — é a mesma informação
    que qualquer cliente da rede recebe por DHCP/RA. O resultado é avaliado por
    perfil porque o baseline e os alertas são por perfil.
    """
    from flask import current_app

    from app.models import Profile

    if not is_dns_check_enabled(current_app):
        logger.debug("Verificação de DNS desabilitada.")
        return

    timeout = float(current_app.config.get("DNS_QUERY_TIMEOUT", 3))
    profiles = Profile.query.filter_by(is_active=True).all()
    if not profiles:
        return

    for profile in profiles:
        state = check_resolver_list(profile)
        servers = state["current"]
        if not servers:
            continue
        result = check_anchor_domains(profile, servers, timeout=timeout)
        logger.info(
            "Verificação DNS (%s): %d resolvedor(es), %d consulta(s), "
            "%d divergência(s), %d sem resposta.",
            profile.name, len(servers), result["checked"],
            len(result["mismatches"]), result["errors"],
        )

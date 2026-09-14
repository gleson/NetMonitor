"""Checagem de configurações inseguras conhecidas (SMB e SNMP).

Diferente da correlação de CVEs, que pergunta "esta versão tem falha
publicada?", aqui a pergunta é "este serviço está configurado de um jeito que
dispensa falha nenhuma?". São as brechas que mais sobrevivem em rede interna
porque ninguém as vê: o padrão de fábrica nunca foi trocado.

Dois alvos, escolhidos por relação valor/esforço:

- **SMB** — SMBv1 habilitado (vetor de EternalBlue/WannaCry, sem correção
  possível a não ser desligar) e assinatura de mensagem não exigida (permite
  *NTLM relay*: o atacante repassa a autenticação da vítima para outro host e
  entra como ela, sem nunca descobrir a senha).
- **SNMP** — comunidade padrão (``public``/``private``) ainda aceita. Quem
  estiver na rede lê a configuração inteira do equipamento; em ponto de acesso
  isso costuma incluir a chave do Wi-Fi, e ``private`` normalmente dá escrita.

Ambos são especialmente comuns em **impressoras, câmeras e pontos de acesso** —
equipamentos que entram na rede, funcionam, e nunca mais são tocados.

Nenhuma das duas checagens precisa de root: os scripts NSE de SMB usam conexão
TCP comum e o SNMP vai por pysnmp. Os achados viram linhas de ``Vulnerability``
(mesma tela e mesmo export das demais) e alertas ``INSECURE_CONFIG``.
"""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Portas que indicam um serviço SMB ao qual vale perguntar.
SMB_PORTS = (445, 139)

# Comunidades de fábrica testadas. Mantido curto de propósito: isto é uma
# checagem de configuração, não uma tentativa de quebra por força bruta.
DEFAULT_SNMP_COMMUNITIES = ("public", "private")

# Scripts NSE usados. smb-protocols lista os dialetos aceitos; os dois de
# security-mode cobrem SMB1 e SMB2+ separadamente.
_SMB_SCRIPTS = "smb-protocols,smb-security-mode,smb2-security-mode"

# "NT LM 0.12 (SMBv1)" na lista de dialetos aceitos.
_SMBV1_RE = re.compile(r"SMBv1", re.IGNORECASE)

# "Message signing enabled but not required" (SMB2) e
# "message_signing: disabled (dangerous, but default)" (SMB1).
_SIGNING_WEAK_RE = re.compile(
    r"signing\s+enabled\s+but\s+not\s+required|message_signing:\s*disabled",
    re.IGNORECASE,
)


def is_hardening_enabled(app=None) -> bool:
    """True se as checagens de configuração insegura devem rodar."""
    from flask import current_app

    from app.models import AppSetting

    cfg = app.config if app is not None else current_app.config
    default = bool(cfg.get("HARDENING_CHECKS_ENABLED", True))
    try:
        raw = AppSetting.get_value("hardening.enabled", "")
    except Exception:
        return default
    if raw == "":
        return default
    return raw in ("1", "true", "True", "on", "yes")


def set_hardening_enabled(enabled: bool) -> None:
    from app.models import AppSetting

    AppSetting.set_value("hardening.enabled", "1" if enabled else "0")


# ---------------------------------------------------------------------------
# SMB
# ---------------------------------------------------------------------------

def parse_smb_output(outputs: dict[str, str]) -> list[dict]:
    """Interpreta a saída dos scripts NSE de SMB.

    Args:
        outputs: {nome_do_script: saída}.

    Returns:
        Lista de achados ``{script, titulo, detalhe, severidade}``. Vazia quando
        a configuração está correta — ausência de achado é o resultado bom.
    """
    findings = []
    protocols = outputs.get("smb-protocols", "")
    if protocols and _SMBV1_RE.search(protocols):
        findings.append({
            "script": "smb-protocols",
            "titulo": "SMBv1 habilitado",
            "detalhe": (
                "O host ainda aceita o dialeto SMBv1, protocolo obsoleto e sem "
                "correção possível — é o vetor de EternalBlue/WannaCry. "
                "A única solução é desabilitá-lo no equipamento."
            ),
            "severidade": "CRITICAL",
        })

    for script in ("smb2-security-mode", "smb-security-mode"):
        out = outputs.get(script, "")
        if out and _SIGNING_WEAK_RE.search(out):
            findings.append({
                "script": script,
                "titulo": "Assinatura SMB não exigida",
                "detalhe": (
                    "A assinatura de mensagens SMB não é obrigatória. Isso "
                    "permite NTLM relay: um atacante no caminho repassa a "
                    "autenticação da vítima para outro host e entra como ela, "
                    "sem precisar descobrir a senha."
                ),
                "severidade": "WARNING",
            })
            break  # um achado por host basta; SMB1 e SMB2 dizem a mesma coisa

    return findings


def check_smb(ip: str, timeout: int = 60) -> list[dict]:
    """Roda os scripts NSE de SMB num host e devolve os achados.

    Não requer root: os scripts falam SMB por conexão TCP comum. Falha de rede
    ou host sem SMB devolve lista vazia — ausência de resposta nunca é achado.
    """
    import nmap

    try:
        nm = nmap.PortScanner()
        ports = ",".join(str(p) for p in SMB_PORTS)
        nm.scan(
            hosts=ip,
            arguments=f"-Pn -p {ports} --script {_SMB_SCRIPTS} -T4 "
                      f"--host-timeout {timeout}s",
        )
    except Exception as exc:
        logger.debug("Scan SMB falhou para %s: %s", ip, exc)
        return []

    outputs: dict[str, str] = {}
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port_num in nm[host][proto]:
                for name, out in (nm[host][proto][port_num].get("script") or {}).items():
                    outputs[name] = outputs.get(name, "") + "\n" + out
        # Alguns dos scripts podem sair como host script em vez de port script.
        for script in nm[host].get("hostscript", []) or []:
            name = script.get("id", "")
            if name:
                outputs[name] = outputs.get(name, "") + "\n" + script.get("output", "")

    return parse_smb_output(outputs)


# ---------------------------------------------------------------------------
# SNMP
# ---------------------------------------------------------------------------

def check_snmp_defaults(ip: str, communities=None, timeout: int = 2) -> list[dict]:
    """Testa se o host responde a alguma comunidade SNMP de fábrica.

    Um GET no ``sysDescr`` por comunidade — um pacote UDP cada. Resposta
    significa que qualquer um na rede lê a configuração do equipamento.
    """
    from app.scanner.snmp import OID_SYS_DESCR, SnmpCredential, snmp_get

    findings = []
    for community in (communities or DEFAULT_SNMP_COMMUNITIES):
        try:
            value = snmp_get(
                ip, OID_SYS_DESCR, timeout=timeout,
                credential=SnmpCredential(version="2c", community=community),
            )
        except Exception as exc:
            logger.debug("SNMP %s@%s falhou: %s", community, ip, exc)
            continue
        if not value:
            continue

        escrita = community == "private"
        findings.append({
            "script": "snmp-default-community",
            "titulo": f"Comunidade SNMP padrão aceita ('{community}')",
            "detalhe": (
                f"O host respondeu a um SNMP GET com a comunidade de fábrica "
                f"'{community}'. Qualquer um na rede lê a configuração completa "
                "do equipamento — em ponto de acesso isso costuma incluir a "
                "chave do Wi-Fi."
                + (" A comunidade 'private' normalmente concede **escrita**, "
                   "permitindo reconfigurar o equipamento." if escrita else "")
                + f" Resposta: {str(value)[:160]}"
            ),
            "severidade": "CRITICAL",
            "community": community,
        })
    return findings


# ---------------------------------------------------------------------------
# Job
# ---------------------------------------------------------------------------

def _hosts_with_smb(profile_id: int) -> set[int]:
    """Ids de devices do perfil com alguma porta SMB aberta."""
    from app.extensions import db
    from app.models import Device, Port

    rows = (
        db.session.query(Port.device_id)
        .join(Device, Port.device_id == Device.id)
        .filter(
            Device.profile_id == profile_id,
            Port.last_seen_closed_at.is_(None),
            Port.state == "open",
            Port.port.in_(SMB_PORTS),
            Port.protocol.in_(("tcp", "tcp6")),
        )
        .distinct()
        .all()
    )
    return {r[0] for r in rows}


def _hosts_with_snmp_port(profile_id: int) -> set[int]:
    from app.extensions import db
    from app.models import Device, Port

    rows = (
        db.session.query(Port.device_id)
        .join(Device, Port.device_id == Device.id)
        .filter(
            Device.profile_id == profile_id,
            Port.last_seen_closed_at.is_(None),
            Port.port == 161,
        )
        .distinct()
        .all()
    )
    return {r[0] for r in rows}


def run_hardening_checks(profile_id: int) -> dict:
    """Job por perfil: procura configurações inseguras nos ativos online.

    SMB é perguntado só a quem tem 445/139 aberto. SNMP, por padrão, a **todos**
    os ativos online: a porta 161 é UDP e só apareceria no scan UDP semanal, que
    exige root — justamente os equipamentos que mais têm comunidade padrão
    (impressora, câmera, ponto de acesso) nunca seriam cobertos. Um pacote UDP
    por comunidade é custo desprezível. ``HARDENING_SNMP_PROBE_ALL=0`` restringe
    aos hosts com 161 já mapeada.
    """
    from flask import current_app

    from app.extensions import db
    from app.models import AlertType, Device, Profile, Severity
    from app.scanner.scheduling import (
        _online_devices_with_ip, _utcnow, emit_alert, upsert_vulnerability_row,
    )

    stats = {"devices": 0, "smb_checked": 0, "snmp_checked": 0, "findings": 0, "alerts": 0}

    profile = db.session.get(Profile, profile_id)
    if profile is None or not profile.is_active:
        return stats
    if not is_hardening_enabled(current_app):
        logger.debug("Checagens de configuração insegura desabilitadas.")
        return stats

    probe_all_snmp = bool(current_app.config.get("HARDENING_SNMP_PROBE_ALL", True))
    max_workers = max(1, int(current_app.config.get("HARDENING_MAX_WORKERS", 10)))
    smb_hosts = _hosts_with_smb(profile_id)
    snmp_hosts = None if probe_all_snmp else _hosts_with_snmp_port(profile_id)

    now = _utcnow()
    targets = []
    for device, device_ip in _online_devices_with_ip(profile_id):
        do_smb = device.id in smb_hosts
        do_snmp = snmp_hosts is None or device.id in snmp_hosts
        if not (do_smb or do_snmp):
            continue
        targets.append((device.id, device.display_name, device_ip.ip, do_smb, do_snmp))
        stats["devices"] += 1
        stats["smb_checked"] += int(do_smb)
        stats["snmp_checked"] += int(do_snmp)

    # A sondagem é toda rede e nenhum banco, então roda em paralelo; a gravação
    # fica serial na thread principal, com a sessão do SQLAlchemy. Sem isso, o
    # tempo de espera dos timeouts de SNMP e dos scans NSE se soma host a host —
    # numa rede de ~140 ativos o job levaria minutos.
    def _probe(target):
        _id, _nome, ip, do_smb, do_snmp = target
        findings = []
        if do_smb:
            findings += check_smb(ip)
        if do_snmp:
            findings += check_snmp_defaults(ip)
        return target, findings

    results = []
    if targets:
        with ThreadPoolExecutor(max_workers=min(max_workers, len(targets))) as executor:
            for future in as_completed([executor.submit(_probe, t) for t in targets]):
                try:
                    results.append(future.result())
                except Exception:
                    logger.exception("Erro na sondagem de configuração insegura.")

    checked_ids: set[int] = set()
    for (device_id, display_name, ip, _s, _n), findings in results:
        checked_ids.add(device_id)
        device = db.session.get(Device, device_id)
        if device is None:
            continue

        for f in findings:
            stats["findings"] += 1
            severity = getattr(Severity, f["severidade"])
            # A comunidade entra na chave: 'public' e 'private' são achados
            # distintos e precisam poder ser resolvidos separadamente.
            script_name = f["script"]
            if f.get("community"):
                script_name = f"{script_name}:{f['community']}"

            is_new = upsert_vulnerability_row(
                device_id=device_id, script_name=script_name, port=0, protocol="",
                service=f["script"].split("-")[0], output=f["detalhe"][:1000],
                is_vulnerable=True, now=now,
            )
            if not is_new:
                continue

            alert = emit_alert(
                profile_id, device_id, AlertType.INSECURE_CONFIG, severity,
                f"{f['titulo']} em {display_name} ({ip}). {f['detalhe']}",
                match_value=script_name,
                is_priority=(severity == Severity.CRITICAL),
                notify_profile=profile, notify_device=device,
            )
            if alert is not None:
                stats["alerts"] += 1
                logger.warning(
                    "INSECURE_CONFIG (%s): %s em %s", profile.name, f["titulo"], ip
                )

    # Achado que não reapareceu num host efetivamente verificado = corrigido.
    stats["resolved"] = _resolve_absent_findings(checked_ids, now)
    db.session.commit()
    logger.info(
        "Checagem de configuração (%s): %d ativo(s), %d SMB, %d SNMP, "
        "%d achado(s), %d alerta(s).",
        profile.name, stats["devices"], stats["smb_checked"],
        stats["snmp_checked"], stats["findings"], stats["alerts"],
    )
    return stats


# Prefixos de script_name gerados por este módulo — usados para saber quais
# linhas de Vulnerability são nossas na hora de resolver as ausentes.
_OWNED_SCRIPT_PREFIXES = ("smb-protocols", "smb-security-mode",
                          "smb2-security-mode", "snmp-default-community")


def _resolve_absent_findings(checked_device_ids: set[int], now) -> int:
    """Marca como resolvido o achado que não foi revisto nesta execução.

    Restrito a duas coisas, e as duas importam: linhas criadas por este módulo
    (pelo prefixo do ``script_name``) e ativos que **foram efetivamente
    verificados agora**. Um host offline não pode ter o achado dele apagado por
    ausência — some da varredura, não do equipamento.

    Returns: quantidade resolvida.
    """
    from app.extensions import db
    from app.models import Vulnerability

    if not checked_device_ids:
        return 0

    rows = (
        db.session.query(Vulnerability)
        .filter(
            Vulnerability.device_id.in_(checked_device_ids),
            Vulnerability.resolved_at.is_(None),
            Vulnerability.is_vulnerable.is_(True),
            Vulnerability.last_seen_at < now,
            db.or_(*[
                Vulnerability.script_name.like(f"{p}%") for p in _OWNED_SCRIPT_PREFIXES
            ]),
        )
        .all()
    )
    for row in rows:
        row.resolved_at = now
        row.is_vulnerable = False
    if rows:
        logger.info("%d achado(s) de configuração resolvido(s).", len(rows))
    return len(rows)

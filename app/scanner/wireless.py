"""Vigilância do ambiente Wi-Fi: ponto de acesso não autorizado e evil twin.

Um *evil twin* é um ponto de acesso que anuncia o **mesmo SSID** de uma rede
legítima. Quem se associa a ele entrega todo o tráfego ao atacante antes de
qualquer pacote chegar à rede cabeada — nenhuma das detecções de
``app/scanner/mitm.py`` enxerga isso, porque o desvio acontece na camada de
rádio, fora do alcance de ARP, NDP, DHCP ou DNS. A variante mais eficaz sequer
precisa da senha: basta anunciar o SSID conhecido **aberto**, contando com o
cliente que prefere sinal forte e conexão sem senha.

A leitura do ambiente é feita pelo NetworkManager (``nmcli dev wifi list``), que
**não exige root nem modo monitor** — a placa faz a varredura normal de rede que
já faria para roaming. Modo monitor permitiria também ver desautenticação
forçada e clientes associados, mas custa a interface inteira (ela sai da rede
enquanto captura); a varredura comum entrega o que importa para evil twin, que é
o par SSID↔BSSID.

Três achados, todos emitindo ``ROGUE_AP``:

- **BSSID novo anunciando um SSID vigiado** — a assinatura do evil twin. Quando
  o rádio novo é de outro fabricante (OUI diferente de todos os conhecidos
  daquele SSID) é CRÍTICO; mesmo fabricante costuma ser repetidor ou mesh
  legítimo e fica em AVISO.
- **Clone aberto** — SSID vigiado que só existia protegido aparecendo sem
  criptografia. Crítico independente do fabricante: é o golpe clássico.
- **Rebaixamento de segurança** — um BSSID conhecido que trocou WPA2/WPA3 por
  WEP/WPA1 ou por rede aberta.

**Só alerta para os SSIDs vigiados.** O monitor não tem como adivinhar quais
redes ao alcance são suas, e alertar sobre as do vizinho seria só ruído. A lista
fica em ``AppSetting`` por perfil, editável em Admin → Configurações de Scan, e
é semeada automaticamente com a rede à qual o próprio host está associado.
"""

import logging
import subprocess

logger = logging.getLogger(__name__)

# Baselines/configuração em AppSetting (por perfil), mesmo formato dos demais.
KEY_WIFI_BASELINE = "wifi.baseline"
KEY_WATCHED_SSIDS = "wifi.watched_ssids"

_KEY_ENABLED = "wifi.watch_enabled"
_TRUTHY = ("1", "true", "True", "on", "yes")

# Campos pedidos ao nmcli, na ordem em que voltam no modo terso.
_FIELDS = ("IN-USE", "SSID", "BSSID", "CHAN", "SIGNAL", "SECURITY", "MODE")

# Tetos de aprendizado: um atacante que rotacione BSSIDs não pode encher o
# baseline até que qualquer rádio futuro passe por conhecido.
_MAX_BSSIDS_PER_SSID = 16
_MAX_SSIDS = 64

# Classes de segurança, da mais fraca para a mais forte. O que interessa é a
# ordem relativa: alertamos quando um SSID *desce* de classe.
_SEC_OPEN, _SEC_WEAK, _SEC_STRONG = 0, 1, 2
_SEC_LABEL = {_SEC_OPEN: "aberta (sem criptografia)", _SEC_WEAK: "fraca (WEP/WPA1)", _SEC_STRONG: "WPA2/WPA3"}


def is_wifi_watch_enabled(app=None) -> bool:
    """True se a vigilância do ambiente Wi-Fi deve rodar (AppSetting > config)."""
    from flask import current_app

    from app.models import AppSetting

    cfg = app.config if app is not None else current_app.config
    default = bool(cfg.get("WIFI_WATCH_ENABLED", True))
    try:
        raw = AppSetting.get_value(_KEY_ENABLED, "")
    except Exception:
        return default
    if raw == "":
        return default
    return raw in _TRUTHY


def set_wifi_watch_enabled(enabled: bool) -> None:
    from app.models import AppSetting

    AppSetting.set_value(_KEY_ENABLED, "1" if enabled else "0")


# ---------------------------------------------------------------------------
# Leitura do ambiente
# ---------------------------------------------------------------------------

def _split_terse(line: str) -> list[str]:
    """Separa uma linha do ``nmcli -t`` respeitando o escape ``\\:``.

    SSID e BSSID contêm dois-pontos; o nmcli os escapa, então um ``split(":")``
    ingênuo quebraria todo MAC em seis campos.
    """
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    return fields


def is_wifi_available() -> bool:
    """True se este host tem alguma interface Wi-Fi gerenciada pelo NetworkManager."""
    try:
        proc = subprocess.run(
            ["nmcli", "-t", "-f", "TYPE", "device"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return any(line.strip() == "wifi" for line in proc.stdout.splitlines())


def scan_wifi_networks(rescan: bool = True, timeout: int = 60) -> list[dict]:
    """Lista os pontos de acesso ao alcance.

    ``rescan=True`` força o NetworkManager a varrer as faixas em vez de devolver
    o cache. É o que garante dado fresco no intervalo de horas do job; o custo é
    a placa sair do canal por algumas centenas de milissegundos. Se o rescan for
    recusado (algumas versões negam enquanto conectado), cai para o cache.

    Redes com SSID oculto vêm com o nome vazio e são descartadas: sem SSID não
    há como dizer se clonam uma rede vigiada.
    """
    base = ["nmcli", "-t", "-f", ",".join(_FIELDS), "device", "wifi", "list"]
    attempts = [base + ["--rescan", "yes"], base] if rescan else [base]

    output = ""
    for cmd in attempts:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            logger.debug("nmcli não encontrado — vigilância Wi-Fi indisponível.")
            return []
        except (OSError, subprocess.TimeoutExpired):
            logger.warning("Falha ao listar redes Wi-Fi (%s).", " ".join(cmd), exc_info=True)
            continue
        if proc.returncode == 0:
            output = proc.stdout
            break
        logger.debug("nmcli retornou %d: %s", proc.returncode, proc.stderr.strip())

    networks = []
    for line in output.splitlines():
        parts = _split_terse(line)
        if len(parts) < len(_FIELDS):
            continue
        in_use, ssid, bssid, chan, signal, security, mode = parts[:len(_FIELDS)]
        ssid = ssid.strip()
        bssid = bssid.strip().upper()
        if not ssid or not bssid:
            continue
        networks.append({
            "in_use": in_use.strip() == "*",
            "ssid": ssid,
            "bssid": bssid,
            "chan": chan.strip(),
            "signal": signal.strip(),
            "security": security.strip(),
            "mode": mode.strip(),
        })
    return networks


# ---------------------------------------------------------------------------
# SSIDs vigiados
# ---------------------------------------------------------------------------

def get_watched_ssids(profile_id: int) -> list[str]:
    """SSIDs que este perfil considera seus. Vazio = só aprende, não alerta."""
    from app.models import AppSetting

    raw = AppSetting.get_value(f"{KEY_WATCHED_SSIDS}.{profile_id}", "")
    return [s.strip() for s in raw.split("\n") if s.strip()]


def set_watched_ssids(profile_id: int, ssids) -> None:
    from app.models import AppSetting

    cleaned, seen = [], set()
    for ssid in ssids:
        ssid = (ssid or "").strip()
        if ssid and ssid not in seen:
            seen.add(ssid)
            cleaned.append(ssid)
    AppSetting.set_value(f"{KEY_WATCHED_SSIDS}.{profile_id}", "\n".join(cleaned))


def parse_watched_input(text: str) -> list[str]:
    """Converte o textarea do admin (um SSID por linha) em lista.

    Não aceita vírgula como separador de propósito: SSID pode conter vírgula, e
    uma rede com nome ``Casa, 2G`` viraria duas entradas que nunca casariam.
    """
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Classificação
# ---------------------------------------------------------------------------

def security_class(security: str) -> int:
    """Classe de segurança de um anúncio: aberta < WEP/WPA1 < WPA2/WPA3."""
    value = (security or "").upper().replace("--", "").strip()
    if not value:
        return _SEC_OPEN
    if "WPA3" in value or "WPA2" in value:
        return _SEC_STRONG
    if "WEP" in value or "WPA" in value:
        return _SEC_WEAK
    return _SEC_WEAK


def oui(bssid: str) -> str:
    """Três primeiros octetos do BSSID — identifica o fabricante do rádio."""
    return ":".join(bssid.upper().split(":")[:3])


# ---------------------------------------------------------------------------
# Verificação
# ---------------------------------------------------------------------------

def check_wireless_environment(profile, networks=None) -> dict:
    """Compara o ambiente Wi-Fi com o baseline do perfil e alerta em desvio.

    Na primeira execução apenas aprende — a rede é assumida limpa no momento da
    instalação, como nos demais baselines. SSIDs fora da lista de vigiados são
    aprendidos em silêncio: servem de histórico do ambiente, mas o vizinho
    trocando de roteador não é problema deste monitor.

    Returns:
        dict com ``learned`` (SSIDs memorizados agora), ``findings`` (lista de
        (ssid, bssid, motivo)) e ``watched``.
    """
    from app.extensions import db
    from app.models import AlertType, Severity
    from app.scanner.mitm import get_baseline, set_baseline
    from app.scanner.scheduling import emit_alert

    if networks is None:
        networks = scan_wifi_networks()

    result = {"learned": [], "findings": [], "watched": []}
    if not networks:
        return result

    watched = get_watched_ssids(profile.id)
    if not watched:
        # Semeia com a rede à qual o próprio host está associado: é a única que
        # o monitor pode afirmar ser dele sem perguntar. Continua editável.
        associated = [n["ssid"] for n in networks if n["in_use"]]
        if associated:
            set_watched_ssids(profile.id, associated)
            watched = associated
            logger.info(
                "SSIDs vigiados do perfil '%s' semeados com a rede associada: %s",
                profile.name, ", ".join(associated),
            )
    result["watched"] = watched
    watched_set = set(watched)

    baseline = get_baseline(KEY_WIFI_BASELINE, profile.id)
    first_run = not baseline

    # SSID -> {BSSID: segurança anunciada} visto agora.
    seen: dict[str, dict[str, str]] = {}
    for net in networks:
        seen.setdefault(net["ssid"], {})[net["bssid"]] = net["security"]

    for ssid, bssids in seen.items():
        known = baseline.get(ssid)
        # ``not known`` cobre o SSID que está no baseline mas ficou sem nenhum
        # BSSID (teto de aprendizado): sem referência não há o que comparar.
        learning = first_run or not known or ssid not in watched_set

        if learning:
            if known is None and len(baseline) >= _MAX_SSIDS:
                logger.warning(
                    "Baseline Wi-Fi do perfil %d cheio (%d SSIDs) — %r não memorizado.",
                    profile.id, len(baseline), ssid,
                )
                continue
            entry = baseline.setdefault(ssid, {})
            for bssid, security in bssids.items():
                if bssid not in entry and len(entry) < _MAX_BSSIDS_PER_SSID:
                    entry[bssid] = security
            if known is None:
                result["learned"].append(ssid)
            continue

        known_ouis = {oui(b) for b in known}
        # Classe do SSID como um todo: se ele existe protegido em algum rádio,
        # um rádio aberto com o mesmo nome é clone, não configuração.
        best_known = max((security_class(s) for s in known.values()), default=_SEC_OPEN)

        for bssid, security in bssids.items():
            prior = known.get(bssid)
            now_class = security_class(security)

            if prior is None:
                if now_class == _SEC_OPEN and best_known > _SEC_OPEN:
                    severity, priority = Severity.CRITICAL, True
                    motivo = (
                        f"ponto de acesso novo ({bssid}) anunciando a rede {ssid!r} "
                        "SEM criptografia, enquanto a rede legítima é protegida. "
                        "É a forma clássica de evil twin: o cliente que preferir o "
                        "sinal mais forte entrega a sessão inteira ao atacante."
                    )
                elif oui(bssid) not in known_ouis:
                    severity, priority = Severity.CRITICAL, True
                    motivo = (
                        f"ponto de acesso novo ({bssid}) anunciando a rede {ssid!r}. "
                        f"O fabricante do rádio ({oui(bssid)}) não coincide com nenhum "
                        "dos já conhecidos desta rede — assinatura de evil twin."
                    )
                else:
                    severity, priority = Severity.WARNING, False
                    motivo = (
                        f"BSSID novo ({bssid}) na rede {ssid!r}, do mesmo fabricante "
                        f"({oui(bssid)}) dos rádios já conhecidos. Costuma ser repetidor "
                        "ou mesh legítimo; confirme se foi instalado agora."
                    )
            elif now_class < security_class(prior):
                severity, priority = Severity.CRITICAL, True
                motivo = (
                    f"o ponto de acesso {bssid} da rede {ssid!r} rebaixou a segurança "
                    f"de {_SEC_LABEL[security_class(prior)]} para {_SEC_LABEL[now_class]}. "
                    "Ou a configuração do equipamento foi alterada, ou outro rádio "
                    "assumiu o BSSID."
                )
            else:
                known[bssid] = security
                continue

            if len(known) < _MAX_BSSIDS_PER_SSID:
                known[bssid] = security  # aceita o novo estado: alerta uma vez
            result["findings"].append((ssid, bssid, motivo))
            emit_alert(
                profile.id, None, AlertType.ROGUE_AP, severity, motivo,
                match_value=f"{ssid}|{bssid}", is_priority=priority,
                notify_profile=profile,
            )
            logger.warning("ROGUE_AP (%s): %s", profile.name, motivo)

    if len(baseline) > _MAX_SSIDS:
        logger.warning("Baseline Wi-Fi do perfil %d com %d SSIDs.", profile.id, len(baseline))
    set_baseline(KEY_WIFI_BASELINE, profile.id, baseline)
    db.session.commit()
    return result


def watch_wireless_environment():
    """Job global: varre o ambiente Wi-Fi e avalia cada perfil ativo.

    A varredura é do **host do monitor** (uma só, compartilhada), mas baseline e
    alertas são por perfil, como em ``dns_check.check_dns_integrity``.
    """
    from flask import current_app

    from app.models import Profile

    if not is_wifi_watch_enabled(current_app):
        logger.debug("Vigilância de ambiente Wi-Fi desabilitada.")
        return

    networks = scan_wifi_networks()
    if not networks:
        logger.info("Nenhuma rede Wi-Fi ao alcance (ou host sem interface sem fio).")
        return

    for profile in Profile.query.filter_by(is_active=True).all():
        try:
            result = check_wireless_environment(profile, networks)
        except Exception:
            logger.exception("Erro na vigilância Wi-Fi do perfil %d.", profile.id)
            continue
        logger.info(
            "Wi-Fi (%s): %d rede(s) visível(is), %d vigiada(s), %d nova(s) memorizada(s), "
            "%d achado(s).",
            profile.name, len({n["ssid"] for n in networks}), len(result["watched"]),
            len(result["learned"]), len(result["findings"]),
        )

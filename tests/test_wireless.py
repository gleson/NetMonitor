"""Testes da vigilância do ambiente Wi-Fi (evil twin / AP não autorizado)."""

from app.models import Alert, AlertType, Device, Severity
from app.scanner import wireless
from app.scanner.mitm import get_baseline, set_baseline


# Saída real do `nmcli -t -f IN-USE,SSID,BSSID,CHAN,SIGNAL,SECURITY,MODE dev wifi list`.
_NMCLI_SAIDA = r""" :DISP:6A\:83\:E7\:6C\:C5\:9E:1:87:WPA1 WPA2:Infra
*:CDVHS_AP_5G:60\:83\:E7\:6C\:C5\:9F:36:69:WPA1 WPA2:Infra
 :Palhoca Comunitaria_EXT:00\:31\:92\:F5\:7E\:87:11:34:WPA1 WPA2:Infra
 ::E2\:44\:89\:BB\:E8\:BA:10:25:WPA2:Infra
 :Cafe Livre:AA\:BB\:CC\:11\:22\:33:6:40::Infra
"""


def _redes(*tuplas):
    """Atalho: (ssid, bssid, security[, in_use]) -> dicts como scan_wifi_networks."""
    out = []
    for t in tuplas:
        ssid, bssid, security = t[0], t[1], t[2]
        out.append({
            "in_use": t[3] if len(t) > 3 else False,
            "ssid": ssid, "bssid": bssid, "chan": "6", "signal": "70",
            "security": security, "mode": "Infra",
        })
    return out


# ---------------------------------------------------------------------------
# Parsing da saída do nmcli
# ---------------------------------------------------------------------------

def test_split_terse_preserva_os_dois_pontos_escapados():
    campos = wireless._split_terse(r"MinhaRede:AA\:BB\:CC\:DD\:EE\:FF:6:70:WPA2:Infra")
    assert campos == ["MinhaRede", "AA:BB:CC:DD:EE:FF", "6", "70", "WPA2", "Infra"]


def test_split_terse_aceita_ssid_com_dois_pontos():
    campos = wireless._split_terse(r"Casa\: 2G:AA\:BB\:CC\:DD\:EE\:FF:6:70:WPA2:Infra")
    assert campos[0] == "Casa: 2G"
    assert campos[1] == "AA:BB:CC:DD:EE:FF"


def test_scan_wifi_networks_parseia_saida_real(monkeypatch):
    class _Proc:
        returncode = 0
        stdout = _NMCLI_SAIDA
        stderr = ""

    monkeypatch.setattr(wireless.subprocess, "run", lambda *a, **k: _Proc())
    redes = wireless.scan_wifi_networks()

    # A linha de SSID oculto (nome vazio) é descartada.
    assert len(redes) == 4
    ssids = {n["ssid"] for n in redes}
    assert "" not in ssids
    assert "Palhoca Comunitaria_EXT" in ssids

    conectada = [n for n in redes if n["in_use"]]
    assert len(conectada) == 1
    assert conectada[0]["ssid"] == "CDVHS_AP_5G"
    assert conectada[0]["bssid"] == "60:83:E7:6C:C5:9F"

    aberta = [n for n in redes if n["ssid"] == "Cafe Livre"][0]
    assert aberta["security"] == ""


def test_scan_wifi_networks_sem_nmcli_retorna_vazio(monkeypatch):
    def _explode(*a, **k):
        raise FileNotFoundError("nmcli")

    monkeypatch.setattr(wireless.subprocess, "run", _explode)
    assert wireless.scan_wifi_networks() == []


def test_scan_cai_para_o_cache_quando_o_rescan_falha(monkeypatch):
    chamadas = []

    class _Proc:
        def __init__(self, rc, out):
            self.returncode, self.stdout, self.stderr = rc, out, "denied"

    def _run(cmd, **kwargs):
        chamadas.append(cmd)
        if "--rescan" in cmd:
            return _Proc(1, "")
        return _Proc(0, _NMCLI_SAIDA)

    monkeypatch.setattr(wireless.subprocess, "run", _run)
    redes = wireless.scan_wifi_networks()
    assert len(chamadas) == 2
    assert len(redes) == 4


# ---------------------------------------------------------------------------
# Classificação
# ---------------------------------------------------------------------------

def test_security_class_ordena_aberta_fraca_forte():
    assert wireless.security_class("") < wireless.security_class("WEP")
    assert wireless.security_class("--") < wireless.security_class("WPA1")
    assert wireless.security_class("WPA1") < wireless.security_class("WPA2")
    assert wireless.security_class("WPA1 WPA2") == wireless.security_class("WPA3")


def test_oui_pega_os_tres_primeiros_octetos():
    assert wireless.oui("60:83:e7:6c:c5:9f") == "60:83:E7"


def test_parse_watched_input_nao_quebra_ssid_com_virgula():
    assert wireless.parse_watched_input("Casa, 2G\n  Escritorio  \n\n") == ["Casa, 2G", "Escritorio"]


# ---------------------------------------------------------------------------
# Baseline e detecção
# ---------------------------------------------------------------------------

def _alertas(profile):
    return Alert.query.filter_by(profile_id=profile.id, alert_type=AlertType.ROGUE_AP).all()


def test_primeira_execucao_so_aprende(db, sample_profile):
    redes = _redes(("MinhaRede", "AA:BB:CC:00:00:01", "WPA2", True),
                   ("Vizinho", "11:22:33:00:00:01", "WPA2"))
    res = wireless.check_wireless_environment(sample_profile, redes)

    assert _alertas(sample_profile) == []
    assert set(res["learned"]) == {"MinhaRede", "Vizinho"}
    base = get_baseline(wireless.KEY_WIFI_BASELINE, sample_profile.id)
    assert base["MinhaRede"] == {"AA:BB:CC:00:00:01": "WPA2"}


def test_semeia_os_vigiados_com_a_rede_associada(db, sample_profile):
    redes = _redes(("MinhaRede", "AA:BB:CC:00:00:01", "WPA2", True),
                   ("Vizinho", "11:22:33:00:00:01", "WPA2"))
    wireless.check_wireless_environment(sample_profile, redes)
    assert wireless.get_watched_ssids(sample_profile.id) == ["MinhaRede"]


def test_bssid_novo_de_outro_fabricante_e_critico(db, sample_profile):
    wireless.set_watched_ssids(sample_profile.id, ["MinhaRede"])
    base = _redes(("MinhaRede", "AA:BB:CC:00:00:01", "WPA2"))
    wireless.check_wireless_environment(sample_profile, base)

    agora = base + _redes(("MinhaRede", "DE:AD:BE:00:00:99", "WPA2"))
    res = wireless.check_wireless_environment(sample_profile, agora)

    alertas = _alertas(sample_profile)
    assert len(alertas) == 1
    assert alertas[0].severity == Severity.CRITICAL
    assert alertas[0].is_priority is True
    assert alertas[0].match_value == "MinhaRede|DE:AD:BE:00:00:99"
    assert "evil twin" in alertas[0].message
    assert len(res["findings"]) == 1


def test_bssid_novo_do_mesmo_fabricante_fica_em_aviso(db, sample_profile):
    wireless.set_watched_ssids(sample_profile.id, ["MinhaRede"])
    base = _redes(("MinhaRede", "AA:BB:CC:00:00:01", "WPA2"))
    wireless.check_wireless_environment(sample_profile, base)

    agora = base + _redes(("MinhaRede", "AA:BB:CC:00:00:02", "WPA2"))
    wireless.check_wireless_environment(sample_profile, agora)

    alertas = _alertas(sample_profile)
    assert len(alertas) == 1
    assert alertas[0].severity == Severity.WARNING
    assert alertas[0].is_priority is False
    assert "repetidor" in alertas[0].message


def test_clone_aberto_e_critico_mesmo_com_o_fabricante_conhecido(db, sample_profile):
    wireless.set_watched_ssids(sample_profile.id, ["MinhaRede"])
    base = _redes(("MinhaRede", "AA:BB:CC:00:00:01", "WPA2"))
    wireless.check_wireless_environment(sample_profile, base)

    agora = base + _redes(("MinhaRede", "AA:BB:CC:00:00:02", ""))
    wireless.check_wireless_environment(sample_profile, agora)

    alertas = _alertas(sample_profile)
    assert len(alertas) == 1
    assert alertas[0].severity == Severity.CRITICAL
    assert "SEM criptografia" in alertas[0].message


def test_rebaixamento_de_seguranca_de_bssid_conhecido(db, sample_profile):
    wireless.set_watched_ssids(sample_profile.id, ["MinhaRede"])
    wireless.check_wireless_environment(
        sample_profile, _redes(("MinhaRede", "AA:BB:CC:00:00:01", "WPA2")))

    wireless.check_wireless_environment(
        sample_profile, _redes(("MinhaRede", "AA:BB:CC:00:00:01", "WEP")))

    alertas = _alertas(sample_profile)
    assert len(alertas) == 1
    assert alertas[0].severity == Severity.CRITICAL
    assert "rebaixou a segurança" in alertas[0].message


def test_melhora_de_seguranca_nao_alerta(db, sample_profile):
    wireless.set_watched_ssids(sample_profile.id, ["MinhaRede"])
    wireless.check_wireless_environment(
        sample_profile, _redes(("MinhaRede", "AA:BB:CC:00:00:01", "WPA1")))
    wireless.check_wireless_environment(
        sample_profile, _redes(("MinhaRede", "AA:BB:CC:00:00:01", "WPA3")))
    assert _alertas(sample_profile) == []


def test_ssid_nao_vigiado_nao_alerta(db, sample_profile):
    wireless.set_watched_ssids(sample_profile.id, ["MinhaRede"])
    base = _redes(("MinhaRede", "AA:BB:CC:00:00:01", "WPA2"),
                  ("Vizinho", "11:22:33:00:00:01", "WPA2"))
    wireless.check_wireless_environment(sample_profile, base)

    agora = base + _redes(("Vizinho", "DE:AD:BE:00:00:99", ""))
    wireless.check_wireless_environment(sample_profile, agora)

    assert _alertas(sample_profile) == []
    # ...mas o rádio novo do vizinho fica memorizado.
    base_salvo = get_baseline(wireless.KEY_WIFI_BASELINE, sample_profile.id)
    assert "DE:AD:BE:00:00:99" in base_salvo["Vizinho"]


def test_alerta_uma_vez_so_por_bssid(db, sample_profile):
    wireless.set_watched_ssids(sample_profile.id, ["MinhaRede"])
    base = _redes(("MinhaRede", "AA:BB:CC:00:00:01", "WPA2"))
    wireless.check_wireless_environment(sample_profile, base)

    agora = base + _redes(("MinhaRede", "DE:AD:BE:00:00:99", "WPA2"))
    wireless.check_wireless_environment(sample_profile, agora)
    wireless.check_wireless_environment(sample_profile, agora)
    wireless.check_wireless_environment(sample_profile, agora)

    assert len(_alertas(sample_profile)) == 1


def test_ssid_vigiado_ausente_do_baseline_e_aprendido_em_silencio(db, sample_profile):
    """O ponto de acesso pode estar desligado na primeira execução."""
    wireless.set_watched_ssids(sample_profile.id, ["MinhaRede", "Deposito"])
    wireless.check_wireless_environment(
        sample_profile, _redes(("MinhaRede", "AA:BB:CC:00:00:01", "WPA2")))

    wireless.check_wireless_environment(
        sample_profile,
        _redes(("MinhaRede", "AA:BB:CC:00:00:01", "WPA2"),
               ("Deposito", "99:88:77:00:00:01", "WPA2")))

    assert _alertas(sample_profile) == []
    assert "Deposito" in get_baseline(wireless.KEY_WIFI_BASELINE, sample_profile.id)


def test_teto_de_bssids_por_ssid(db, sample_profile):
    """Um atacante que rotacione BSSIDs não pode encher o baseline."""
    wireless.set_watched_ssids(sample_profile.id, ["MinhaRede"])
    cheio = {f"AA:BB:CC:00:00:{i:02X}": "WPA2" for i in range(wireless._MAX_BSSIDS_PER_SSID)}
    set_baseline(wireless.KEY_WIFI_BASELINE, sample_profile.id, {"MinhaRede": cheio})

    wireless.check_wireless_environment(
        sample_profile, _redes(("MinhaRede", "AA:BB:CC:00:00:FF", "WPA2")))

    salvo = get_baseline(wireless.KEY_WIFI_BASELINE, sample_profile.id)
    assert len(salvo["MinhaRede"]) == wireless._MAX_BSSIDS_PER_SSID
    assert "AA:BB:CC:00:00:FF" not in salvo["MinhaRede"]
    # O alerta é emitido mesmo assim — o teto limita o aprendizado, não a detecção.
    assert len(_alertas(sample_profile)) == 1


def test_alerta_vincula_o_device_quando_o_bssid_e_conhecido(db, sample_profile):
    """O BSSID não é o MAC do ativo cadastrado, então o alerta fica sem device."""
    db.session.add(Device(profile_id=sample_profile.id, mac="AA:BB:CC:00:00:01",
                          hostname="AP Sala"))
    db.session.commit()
    wireless.set_watched_ssids(sample_profile.id, ["MinhaRede"])
    base = _redes(("MinhaRede", "AA:BB:CC:00:00:01", "WPA2"))
    wireless.check_wireless_environment(sample_profile, base)
    wireless.check_wireless_environment(
        sample_profile, base + _redes(("MinhaRede", "DE:AD:BE:00:00:99", "WPA2")))

    alertas = _alertas(sample_profile)
    assert len(alertas) == 1
    assert alertas[0].device_id is None


def test_ambiente_vazio_nao_mexe_no_baseline(db, sample_profile):
    wireless.set_watched_ssids(sample_profile.id, ["MinhaRede"])
    wireless.check_wireless_environment(
        sample_profile, _redes(("MinhaRede", "AA:BB:CC:00:00:01", "WPA2")))
    antes = get_baseline(wireless.KEY_WIFI_BASELINE, sample_profile.id)

    wireless.check_wireless_environment(sample_profile, [])
    assert get_baseline(wireless.KEY_WIFI_BASELINE, sample_profile.id) == antes
    assert _alertas(sample_profile) == []


def test_job_global_respeita_a_flag(db, sample_profile, monkeypatch, app):
    chamou = []
    monkeypatch.setattr(wireless, "scan_wifi_networks", lambda *a, **k: chamou.append(1) or [])
    wireless.set_wifi_watch_enabled(False)
    db.session.commit()
    wireless.watch_wireless_environment()
    assert chamou == []

    wireless.set_wifi_watch_enabled(True)
    db.session.commit()
    wireless.watch_wireless_environment()
    assert chamou == [1]

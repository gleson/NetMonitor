"""Testes das funções de scanner."""

from app.scanner.hosts import normalize_mac, get_vendor_from_mac
from app.scanner.ports import diff_ports, PortInfo, get_open_ports


class TestNormalizeMac:
    def test_already_normalized(self):
        assert normalize_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"

    def test_lowercase(self):
        assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_dash_separator(self):
        assert normalize_mac("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"

    def test_no_separator(self):
        assert normalize_mac("AABBCCDDEEFF") == "AA:BB:CC:DD:EE:FF"

    def test_dot_separator(self):
        assert normalize_mac("AA.BB.CC.DD.EE.FF") == "AA:BB:CC:DD:EE:FF"


class TestVendorLookup:
    def test_known_vendor(self):
        assert get_vendor_from_mac("00:50:56:11:22:33") == "VMware"

    def test_unknown_vendor(self):
        assert get_vendor_from_mac("FF:FF:FF:00:00:00") == ""

    def test_raspberry_pi(self):
        assert get_vendor_from_mac("B8:27:EB:AA:BB:CC") == "Raspberry Pi"


class TestDiffPorts:
    def test_new_ports(self):
        old = {("tcp", 22), ("tcp", 80)}
        new = {("tcp", 22), ("tcp", 80), ("tcp", 443)}
        opened, closed = diff_ports(old, new)
        assert opened == {("tcp", 443)}
        assert closed == set()

    def test_closed_ports(self):
        old = {("tcp", 22), ("tcp", 80), ("tcp", 443)}
        new = {("tcp", 22)}
        opened, closed = diff_ports(old, new)
        assert opened == set()
        assert closed == {("tcp", 80), ("tcp", 443)}

    def test_mixed_changes(self):
        old = {("tcp", 22), ("tcp", 80)}
        new = {("tcp", 22), ("tcp", 443)}
        opened, closed = diff_ports(old, new)
        assert opened == {("tcp", 443)}
        assert closed == {("tcp", 80)}

    def test_no_changes(self):
        ports = {("tcp", 22), ("tcp", 80)}
        opened, closed = diff_ports(ports, ports)
        assert opened == set()
        assert closed == set()

    def test_empty_to_some(self):
        opened, closed = diff_ports(set(), {("tcp", 22)})
        assert opened == {("tcp", 22)}
        assert closed == set()

    def test_some_to_empty(self):
        opened, closed = diff_ports({("tcp", 22)}, set())
        assert opened == set()
        assert closed == {("tcp", 22)}


class TestGetOpenPorts:
    def test_filters_open(self):
        ports = [
            PortInfo(port=22, protocol="tcp", state="open", service_name="ssh"),
            PortInfo(port=23, protocol="tcp", state="closed", service_name="telnet"),
            PortInfo(port=80, protocol="tcp", state="open", service_name="http"),
            PortInfo(port=443, protocol="tcp", state="filtered", service_name="https"),
        ]
        result = get_open_ports(ports)
        assert len(result) == 2
        assert all(p.state == "open" for p in result)


class TestPruneStaleScanState:
    """Poda diária do estado em memória do scanner (dicts de módulo)."""

    def test_prune_removes_orphans_and_keeps_valid(self, db, sample_profile):
        from collections import deque
        from app.models import Device
        from app.scanner import scheduling

        device = Device(
            profile_id=sample_profile.id,
            mac="AA:BB:CC:DD:EE:77",
            alert_on_down=True,
        )
        db.session.add(device)
        db.session.commit()

        orphan_id = 999_999  # device inexistente / profile inexistente
        try:
            with scheduling._quick_host_down_lock:
                scheduling._quick_host_down_failures[orphan_id] = 2
                scheduling._quick_host_down_failures[device.id] = 1
            with scheduling._port_scan_retry_lock:
                scheduling._port_scan_retry_args[orphan_id] = 1
                scheduling._port_scan_retry_args[device.id] = 0
            with scheduling._port_scan_queues_lock:
                scheduling._port_scan_queues[orphan_id] = deque()
                scheduling._port_scan_queues[sample_profile.id] = deque()

            scheduling._prune_stale_scan_state()

            # Órfãos removidos...
            assert orphan_id not in scheduling._quick_host_down_failures
            assert orphan_id not in scheduling._port_scan_retry_args
            assert orphan_id not in scheduling._port_scan_queues
            # ...entradas válidas preservadas.
            assert device.id in scheduling._quick_host_down_failures
            assert device.id in scheduling._port_scan_retry_args
            assert sample_profile.id in scheduling._port_scan_queues

            # Device sem alert_on_down perde o contador de host-down.
            device.alert_on_down = False
            db.session.commit()
            scheduling._prune_stale_scan_state()
            assert device.id not in scheduling._quick_host_down_failures
            assert device.id in scheduling._port_scan_retry_args  # device existe
        finally:
            # Limpa para não vazar estado para outros testes.
            with scheduling._quick_host_down_lock:
                scheduling._quick_host_down_failures.pop(device.id, None)
                scheduling._quick_host_down_failures.pop(orphan_id, None)
            with scheduling._port_scan_retry_lock:
                scheduling._port_scan_retry_args.pop(device.id, None)
                scheduling._port_scan_retry_args.pop(orphan_id, None)
            with scheduling._port_scan_queues_lock:
                scheduling._port_scan_queues.pop(sample_profile.id, None)
                scheduling._port_scan_queues.pop(orphan_id, None)


class TestPortsVanishedGiveUp:
    """Item #2: após esgotar a sequência de scans alternativos sem reencontrar
    as portas, o scanner desiste e aceita o fechamento — em vez de re-enfileirar
    o device a cada ciclo indefinidamente.
    """

    def test_gives_up_after_retry_sequence(self, db, sample_profile, sample_range, monkeypatch):
        from app.models import Device, DeviceIp, Port, _utcnow
        from app.scanner import scheduling
        import app.scanner.ports as ports_mod
        import app.scanner.hosts as hosts_mod

        now = _utcnow()
        device = Device(
            profile_id=sample_profile.id, mac="AA:BB:CC:DD:EE:88", last_seen_at=now,
        )
        db.session.add(device)
        db.session.flush()
        db.session.add(DeviceIp(
            device_id=device.id, ip="192.168.1.50", is_current=True,
            first_seen_at=now, last_seen_at=now,
        ))
        # Duas portas abertas: >= 2 é o gatilho da heurística de "portas sumidas".
        for pnum in (80, 443):
            db.session.add(Port(
                device_id=device.id, protocol="tcp", port=pnum, state="open",
                first_open_at=now, last_seen_open_at=now,
            ))
        db.session.commit()
        did = device.id

        # Host sempre alcançável; o scan sempre volta com 0 portas (host_found=True).
        monkeypatch.setattr(hosts_mod, "is_host_reachable", lambda ip, *a, **k: (True, "icmp"))
        monkeypatch.setattr(ports_mod, "scan_ports_for_host", lambda *a, **k: ([], True))

        def _open_count():
            return Port.query.filter_by(device_id=did).filter(
                Port.last_seen_closed_at.is_(None)
            ).count()

        try:
            # Dentro da janela de retry as portas continuam abertas (só re-enfileira).
            for _ in range(scheduling._PORT_SCAN_MAX_BUG_RETRIES):
                scheduling.run_port_scan(sample_profile.id)
                assert _open_count() == 2

            # A rodada seguinte excede o limite → desiste e fecha as portas.
            scheduling.run_port_scan(sample_profile.id)
            assert _open_count() == 0
            # O estado de retry do device é limpo ao aceitar o fechamento.
            assert did not in scheduling._port_scan_bug_attempts
            assert did not in scheduling._port_scan_retry_args
        finally:
            with scheduling._port_scan_queues_lock:
                scheduling._port_scan_queues.pop(sample_profile.id, None)
            with scheduling._port_scan_retry_lock:
                scheduling._port_scan_bug_attempts.pop(did, None)
                scheduling._port_scan_retry_args.pop(did, None)


class TestUnreachableHostCooldown:
    """Host que não responde ao port scan deve entrar no cooldown de 24h.

    Sem isso, last_port_scanned_at fica NULL/antigo, o device volta à frente
    da fila (ordenada por esse campo) em toda reconstrução e monopoliza os
    ciclos — devices alcançáveis sofrem inanição.
    """

    def test_unreachable_host_gets_cooldown_and_keeps_ports(
        self, db, sample_profile, sample_range, monkeypatch
    ):
        from app.models import Device, DeviceIp, Port, _utcnow
        from app.scanner import scheduling
        import app.scanner.ports as ports_mod
        import app.scanner.hosts as hosts_mod

        now = _utcnow()
        device = Device(
            profile_id=sample_profile.id, mac="AA:BB:CC:DD:EE:99", last_seen_at=now,
        )
        db.session.add(device)
        db.session.flush()
        db.session.add(DeviceIp(
            device_id=device.id, ip="192.168.1.60", is_current=True,
            first_seen_at=now, last_seen_at=now,
        ))
        db.session.add(Port(
            device_id=device.id, protocol="tcp", port=22, state="open",
            first_open_at=now, last_seen_open_at=now,
        ))
        db.session.commit()
        did = device.id

        # Host inalcançável: reachability falha e o scan reporta host_found=False.
        monkeypatch.setattr(hosts_mod, "is_host_reachable", lambda ip, *a, **k: (False, None))
        monkeypatch.setattr(ports_mod, "scan_ports_for_host", lambda *a, **k: ([], False))

        try:
            scheduling.run_port_scan(sample_profile.id)

            refreshed = db.session.get(Device, did)
            # Cooldown aplicado mesmo sem resposta (evita inanição da fila)...
            assert refreshed.last_port_scanned_at is not None
            # ...mas as portas conhecidas permanecem intactas (invariante).
            open_ports = Port.query.filter_by(device_id=did).filter(
                Port.last_seen_closed_at.is_(None)
            ).count()
            assert open_ports == 1
        finally:
            with scheduling._port_scan_queues_lock:
                scheduling._port_scan_queues.pop(sample_profile.id, None)


class TestOutputIndicatesVulnerable:
    """Interpretação da saída de scripts NSE de vulnerabilidade (#9)."""

    def _f(self, output):
        from app.scanner.scheduling import _output_indicates_vulnerable
        return _output_indicates_vulnerable(output)

    def test_state_vulnerable(self):
        out = (
            "\n  VULNERABLE:\n"
            "  Remote Code Execution vulnerability in Microsoft SMBv1 (ms17-010)\n"
            "    State: VULNERABLE\n"
            "    IDs:  CVE:CVE-2017-0143\n"
        )
        assert self._f(out) is True

    def test_state_not_vulnerable(self):
        # Bug antigo: 'VULNERABLE' é substring de 'NOT VULNERABLE' → falso positivo.
        out = "\n  ms-sql-info:\n    State: NOT VULNERABLE\n"
        assert self._f(out) is False

    def test_state_likely_vulnerable(self):
        out = "\n    State: LIKELY VULNERABLE\n    IDs:  CVE:CVE-2015-1635\n"
        assert self._f(out) is True

    def test_multiple_states_one_positive(self):
        out = (
            "  CVE-2014-0160:\n    State: NOT VULNERABLE\n"
            "  CVE-2014-0224:\n    State: VULNERABLE\n"
        )
        assert self._f(out) is True

    def test_multiple_states_all_negative(self):
        out = (
            "  CVE-2014-0160:\n    State: NOT VULNERABLE\n"
            "  CVE-2014-0224:\n    State: NOT VULNERABLE\n"
        )
        assert self._f(out) is False

    def test_plain_not_vulnerable_without_state_field(self):
        assert self._f("Host is NOT VULNERABLE to this issue.") is False

    def test_free_text_vulnerable(self):
        assert self._f("The target appears VULNERABLE to CVE-2021-1234") is True

    def test_unrelated_output(self):
        assert self._f("http-server-header: Apache/2.4.41 (Ubuntu)") is False

    def test_error_and_unknown_states(self):
        assert self._f("    State: UNKNOWN (unable to test)\n") is False
        assert self._f("ERROR: Script execution failed") is False

    def test_empty_output(self):
        assert self._f("") is False
        assert self._f(None) is False

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

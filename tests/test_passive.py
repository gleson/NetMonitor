"""Testes da descoberta passiva (callback do sniffer ARP + multicast)."""

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether

from app.scanner import passive


@pytest.fixture(autouse=True)
def _clean_buffer():
    with passive._buffer_lock:
        passive._buffer.clear()
    yield
    with passive._buffer_lock:
        passive._buffer.clear()


def _buffer():
    with passive._buffer_lock:
        return dict(passive._buffer)


def test_arp_packet_bufferizado():
    pkt = Ether(src="aa:bb:cc:dd:ee:01") / ARP(
        psrc="192.168.100.62", hwsrc="aa:bb:cc:dd:ee:01", op=1,
    )
    passive._on_packet(pkt)
    assert _buffer() == {"AA:BB:CC:DD:EE:01": "192.168.100.62"}


def test_mdns_multicast_bufferizado():
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:02", dst="01:00:5e:00:00:fb")
        / IP(src="192.168.100.62", dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
    )
    passive._on_packet(pkt)
    assert _buffer() == {"AA:BB:CC:DD:EE:02": "192.168.100.62"}


def test_ssdp_e_broadcast_bufferizados():
    ssdp = (
        Ether(src="aa:bb:cc:dd:ee:03")
        / IP(src="192.168.100.70", dst="239.255.255.250")
        / UDP(sport=50000, dport=1900)
    )
    netbios = (
        Ether(src="aa:bb:cc:dd:ee:04")
        / IP(src="192.168.100.71", dst="192.168.100.255")
        / UDP(sport=137, dport=137)
    )
    passive._on_packet(ssdp)
    passive._on_packet(netbios)
    assert _buffer() == {
        "AA:BB:CC:DD:EE:03": "192.168.100.70",
        "AA:BB:CC:DD:EE:04": "192.168.100.71",
    }


def test_udp_unicast_roteado_ignorado():
    # Unicast: o MAC de origem pode ser do roteador, não do dono do IP.
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:05")
        / IP(src="10.0.0.9", dst="192.168.100.240")
        / UDP(sport=5353, dport=5353)
    )
    passive._on_packet(pkt)
    assert _buffer() == {}


def test_dhcp_discover_sem_ip_ignorado():
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:06")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
    )
    passive._on_packet(pkt)
    assert _buffer() == {}


def test_is_local_only_dst():
    assert passive._is_local_only_dst("224.0.0.251")
    assert passive._is_local_only_dst("239.255.255.250")
    assert passive._is_local_only_dst("255.255.255.255")
    assert passive._is_local_only_dst("192.168.100.255")
    assert not passive._is_local_only_dst("192.168.100.62")
    assert not passive._is_local_only_dst("8.8.8.8")
    assert not passive._is_local_only_dst("")

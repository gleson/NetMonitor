"""Mapeamento de topologia física de camada 2 via SNMP (LLDP + FDB).

Opcional e desligado por padrão (exige switches gerenciáveis com SNMP). Para
cada Device do tipo SWITCH em um perfil, correlaciona:

- **LLDP-MIB** (``lldpRemTable``): vizinhos switch↔switch (nome/porta remota).
- **BRIDGE-MIB** (``dot1dTpFdbPort`` + ``dot1dBasePortIfIndex`` + ``ifName``):
  em qual porta física cada MAC (endpoint) está aprendido — a base para dizer
  "device X está conectado na porta Y do switch Z".

Os achados são persistidos em ``SwitchNeighbor``. O job é registrado apenas
quando ``topology_lldp_enabled`` está ligado (config ou AppSetting).
"""

import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

# --- OIDs ---
# LLDP remote system data
OID_LLDP_REM_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"   # + timeMark.locPortNum.remIndex
OID_LLDP_REM_PORTID = "1.0.8802.1.1.2.1.4.1.1.7"
OID_LLDP_REM_CHASSISID = "1.0.8802.1.1.2.1.4.1.1.5"
OID_LLDP_LOC_PORTID = "1.0.8802.1.1.2.1.3.7.1.3"    # + locPortNum → nome da porta local
# BRIDGE-MIB
OID_DOT1D_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"       # + mac(6 octetos) → bridge port
OID_DOT1D_BASEPORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"  # bridge port → ifIndex
OID_IFNAME = "1.3.6.1.2.1.31.1.1.1.1"               # ifIndex → nome


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def is_topology_enabled(app) -> bool:
    """Flag efetiva (AppSetting tem prioridade sobre a config)."""
    default = bool(app.config.get("TOPOLOGY_LLDP_ENABLED", False))
    try:
        from app.models import AppSetting
        raw = AppSetting.get_value("topology_lldp_enabled", "")
        if raw == "":
            return default
        return raw in ("1", "true", "True", "on")
    except Exception:
        logger.debug("Falha ao ler AppSetting topology_lldp_enabled — usando default.", exc_info=True)
        return default


# ---------------------------------------------------------------------------
# Helpers de parsing de OID
# ---------------------------------------------------------------------------

def _suffix_ints(full_oid: str, base_oid: str) -> list[int]:
    """Componentes inteiros do OID após o prefixo base. [] se não casar."""
    full = full_oid.lstrip(".")
    base = base_oid.lstrip(".")
    if not full.startswith(base):
        return []
    rest = full[len(base):].lstrip(".")
    if not rest:
        return []
    try:
        return [int(x) for x in rest.split(".")]
    except ValueError:
        return []


def _mac_from_octets(octets: list[int]) -> str:
    """Converte 6 octetos decimais (do índice FDB) em MAC AA:BB:...:FF."""
    if len(octets) != 6:
        return ""
    return ":".join(f"{o & 0xFF:02X}" for o in octets)


# ---------------------------------------------------------------------------
# Coleta por switch
# ---------------------------------------------------------------------------

def _collect_lldp_neighbors(ip: str, cred) -> list[dict]:
    """Vizinhos LLDP (switch↔switch). Retorna dicts com local_port/remote_*."""
    from app.scanner.snmp import snmp_walk

    # Nome da porta local por locPortNum.
    loc_ports: dict[int, str] = {}
    for oid, val in snmp_walk(ip, OID_LLDP_LOC_PORTID, credential=cred):
        comps = _suffix_ints(oid, OID_LLDP_LOC_PORTID)
        if comps:
            loc_ports[comps[-1]] = val

    sysnames: dict[tuple, str] = {}
    for oid, val in snmp_walk(ip, OID_LLDP_REM_SYSNAME, credential=cred):
        comps = _suffix_ints(oid, OID_LLDP_REM_SYSNAME)
        if len(comps) >= 3:
            sysnames[tuple(comps[-3:])] = val

    portids: dict[tuple, str] = {}
    for oid, val in snmp_walk(ip, OID_LLDP_REM_PORTID, credential=cred):
        comps = _suffix_ints(oid, OID_LLDP_REM_PORTID)
        if len(comps) >= 3:
            portids[tuple(comps[-3:])] = val

    neighbors = []
    for key, sysname in sysnames.items():
        # key = (timeMark, locPortNum, remIndex)
        loc_port_num = key[1]
        neighbors.append({
            "local_port": loc_ports.get(loc_port_num, str(loc_port_num)),
            "remote_name": sysname,
            "remote_port": portids.get(key, ""),
            "remote_mac": "",
            "source": "lldp",
        })
    return neighbors


def _collect_fdb_entries(ip: str, cred) -> list[dict]:
    """Entradas FDB (MAC → porta física). Retorna dicts com local_port/remote_mac."""
    from app.scanner.snmp import snmp_walk

    # bridge port → ifIndex
    bp_to_ifindex: dict[int, int] = {}
    for oid, val in snmp_walk(ip, OID_DOT1D_BASEPORT_IFINDEX, credential=cred):
        comps = _suffix_ints(oid, OID_DOT1D_BASEPORT_IFINDEX)
        try:
            if comps:
                bp_to_ifindex[comps[-1]] = int(val)
        except (ValueError, TypeError):
            continue

    # ifIndex → nome
    ifname: dict[int, str] = {}
    for oid, val in snmp_walk(ip, OID_IFNAME, credential=cred):
        comps = _suffix_ints(oid, OID_IFNAME)
        if comps:
            ifname[comps[-1]] = val

    entries = []
    for oid, val in snmp_walk(ip, OID_DOT1D_FDB_PORT, credential=cred):
        comps = _suffix_ints(oid, OID_DOT1D_FDB_PORT)
        mac = _mac_from_octets(comps)
        if not mac:
            continue
        try:
            bridge_port = int(val)
        except (ValueError, TypeError):
            continue
        if bridge_port <= 0:
            continue  # 0 = ainda não aprendido
        ifidx = bp_to_ifindex.get(bridge_port)
        port_label = ifname.get(ifidx, f"port {bridge_port}") if ifidx else f"port {bridge_port}"
        entries.append({
            "local_port": port_label,
            "remote_mac": mac,
            "remote_name": "",
            "remote_port": "",
            "source": "fdb",
        })
    return entries


# ---------------------------------------------------------------------------
# Job
# ---------------------------------------------------------------------------

def discover_switch_topology(profile_id: int):
    """Descobre a topologia L2 dos switches de um perfil e persiste vizinhanças.

    Gate: só roda com a flag ligada. Percorre os devices SWITCH do perfil,
    coleta LLDP + FDB via SNMP e faz upsert em SwitchNeighbor, correlacionando
    MACs com Devices existentes.
    """
    from flask import current_app
    from app.extensions import db
    from app.models import Device, DeviceIp, DeviceType, Profile, SwitchNeighbor
    from app.scanner.snmp import credential_from_profile

    if not is_topology_enabled(current_app):
        return

    profile = db.session.get(Profile, profile_id)
    if not profile or not profile.is_active or not profile.snmp_enabled:
        return

    cred = credential_from_profile(profile)

    switches = (
        db.session.query(Device, DeviceIp)
        .join(DeviceIp, (DeviceIp.device_id == Device.id) & DeviceIp.is_current.is_(True))
        .filter(
            Device.profile_id == profile_id,
            Device.device_type == DeviceType.SWITCH,
        )
        .all()
    )
    if not switches:
        logger.info("Topologia '%s': nenhum device SWITCH com IP atual.", profile.name)
        return

    # Índice MAC → device_id para correlação de endpoints (perfil inteiro).
    mac_to_device = {
        d.mac: d.id for d in Device.query.filter_by(profile_id=profile_id).all()
    }

    now = _utcnow()
    total = 0
    for switch, dip in switches:
        ip = dip.ip
        try:
            found = _collect_lldp_neighbors(ip, cred) + _collect_fdb_entries(ip, cred)
        except Exception:
            logger.exception("Erro coletando topologia do switch %s (%s)", switch.display_name, ip)
            continue

        for entry in found:
            remote_mac = entry.get("remote_mac", "")
            # Não registra o próprio switch como vizinho de si mesmo.
            if remote_mac and remote_mac == switch.mac:
                continue
            local_port = entry.get("local_port", "")
            row = SwitchNeighbor.query.filter_by(
                switch_device_id=switch.id,
                local_port=local_port,
                remote_mac=remote_mac,
            ).first()
            if row is None:
                row = SwitchNeighbor(
                    profile_id=profile_id,
                    switch_device_id=switch.id,
                    local_port=local_port,
                    remote_mac=remote_mac,
                    source=entry.get("source", "fdb"),
                    first_seen_at=now,
                    last_seen_at=now,
                )
                db.session.add(row)
            row.remote_name = entry.get("remote_name", "") or row.remote_name
            row.remote_port = entry.get("remote_port", "") or row.remote_port
            row.remote_device_id = mac_to_device.get(remote_mac)
            row.last_seen_at = now
            total += 1

        db.session.commit()

    # Poda vizinhanças não revistas há muito tempo (topologia mudou).
    interval_h = int(current_app.config.get("TOPOLOGY_LLDP_INTERVAL_HOURS", 6))
    stale_cutoff = now - timedelta(hours=max(interval_h * 4, 24))
    stale = SwitchNeighbor.query.filter(
        SwitchNeighbor.profile_id == profile_id,
        SwitchNeighbor.last_seen_at < stale_cutoff,
    )
    removed = stale.count()
    if removed:
        stale.delete(synchronize_session=False)
        db.session.commit()

    logger.info(
        "Topologia '%s': %d vizinhança(s) atualizada(s), %d antiga(s) removida(s).",
        profile.name, total, removed,
    )

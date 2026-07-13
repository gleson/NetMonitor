"""Testes dos endpoints de métricas/timeline (bucketing portátil em Python)."""

from datetime import timedelta

from app.models import Device, DeviceOnlineSnapshot, _utcnow


def _local(dt, app):
    offset = int(app.config.get("LOCAL_TIMEZONE_OFFSET", -3))
    return dt + timedelta(hours=offset)


def test_devices_timeline_buckets_by_local_day(auth_client, db, sample_profile, app):
    """Device visto às 01:00 UTC cai no dia ANTERIOR no fuso local (BRT=-3)."""
    now = _utcnow()
    # 01:00 UTC de hoje → 22:00 local do dia anterior (offset -3).
    edge_utc = now.replace(hour=1, minute=0, second=0, microsecond=0)
    device = Device(
        profile_id=sample_profile.id,
        mac="AA:BB:CC:DD:EE:50",
        first_seen_at=edge_utc,
    )
    db.session.add(device)
    db.session.commit()

    resp = auth_client.get(
        f"/api/metrics/devices-timeline?profile_id={sample_profile.id}&days=7"
    )
    assert resp.status_code == 200
    timeline = resp.get_json()["timeline"]

    expected_day = _local(edge_utc, app).strftime("%Y-%m-%d")
    by_date = {row["date"]: row["new_devices"] for row in timeline}
    assert by_date.get(expected_day) == 1
    # O dia UTC "cru" não deve conter o device (a menos que coincida).
    utc_day = edge_utc.strftime("%Y-%m-%d")
    if utc_day != expected_day:
        assert by_date.get(utc_day, 0) == 0


def test_online_timeline_max_per_local_slot(auth_client, db, sample_profile, app):
    """Vários snapshots no mesmo dia local → prevalece o maior online_count."""
    now = _utcnow()
    base = now - timedelta(days=1)
    for count in (5, 9, 3):
        db.session.add(DeviceOnlineSnapshot(
            profile_id=sample_profile.id,
            recorded_at=base,
            online_count=count,
        ))
    db.session.commit()

    resp = auth_client.get(
        f"/api/metrics/online-timeline?profile_id={sample_profile.id}&period=15days"
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["granularity"] == "day"

    expected_slot = _local(base, app).strftime("%Y-%m-%d")
    by_slot = {row["slot"]: row["online_devices"] for row in data["timeline"]}
    assert by_slot.get(expected_slot) == 9


def test_online_timeline_hour_granularity(auth_client, db, sample_profile, app):
    """Período 'day' agrupa por hora local no formato '%Y-%m-%d %H:00'."""
    now = _utcnow()
    snap_at = now - timedelta(hours=2)
    db.session.add(DeviceOnlineSnapshot(
        profile_id=sample_profile.id,
        recorded_at=snap_at,
        online_count=4,
    ))
    db.session.commit()

    resp = auth_client.get(
        f"/api/metrics/online-timeline?profile_id={sample_profile.id}&period=day"
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["granularity"] == "hour"

    expected_slot = _local(snap_at, app).strftime("%Y-%m-%d %H:00")
    by_slot = {row["slot"]: row["online_devices"] for row in data["timeline"]}
    assert by_slot.get(expected_slot) == 4

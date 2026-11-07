from __future__ import annotations

from datetime import datetime, timedelta

import pandas as pd

from src.correlation import INCIDENT_COLUMNS, correlate_alerts, correlate_events
from src.detection import ALERT_COLUMNS, detect_excessive_auth_failures
from src.load_logs import REQUIRED_COLUMNS

BASE_TIME = datetime(2026, 1, 15, 10, 0, 0)


def _event(
    minutes: float,
    *,
    username: str = "jdoe",
    source_ip: str = "10.0.0.50",
    event_type: str = "AUTH_FAILURE",
    event_id: str | None = None,
    hostname: str | None = "WS-JDOE",
    timestamp: datetime | str | None = None,
) -> dict:
    if timestamp is None:
        ts = BASE_TIME + timedelta(minutes=minutes)
    else:
        ts = timestamp
    suffix = event_id if event_id is not None else f"EVT-{minutes}-{username}-{source_ip}"
    row = {column: pd.NA for column in REQUIRED_COLUMNS}
    row.update(
        {
            "timestamp": ts,
            "source_ip": source_ip,
            "username": username,
            "hostname": hostname if hostname is not None else pd.NA,
            "event_type": event_type,
            "event_id": suffix,
        }
    )
    return row


def _logs(events: list[dict]) -> pd.DataFrame:
    frame = pd.DataFrame(events)
    frame["timestamp"] = pd.to_datetime(
        frame["timestamp"], errors="coerce", utc=True, format="mixed"
    )
    frame["timestamp"] = frame["timestamp"].dt.tz_convert("UTC").dt.tz_localize(None)
    return frame


def test_five_failures_followed_by_success_creates_incident() -> None:
    events = [_event(i, event_id=f"F{i}") for i in range(5)]
    events.append(_event(5.5, event_type="AUTH_SUCCESS", event_id="S1"))

    incidents = correlate_alerts(_logs(events))

    assert len(incidents) == 1
    incident = incidents.iloc[0]
    assert incident["incident_type"] == "possible_brute_force_attack"
    assert incident["username"] == "jdoe"
    assert incident["source_ip"] == "10.0.0.50"
    assert incident["status"] == "needs_investigation"
    assert incident["first_seen"] == _logs(events).iloc[0]["timestamp"]
    assert incident["last_seen"] == _logs(events).iloc[-1]["timestamp"]
    assert set(incident["related_events"]) == {"F0", "F1", "F2", "F3", "F4", "S1"}


def test_different_usernames_are_not_correlated() -> None:
    events = [_event(i, username="alice", event_id=f"A{i}") for i in range(5)]
    events.append(_event(5.5, username="bob", event_type="AUTH_SUCCESS", event_id="B_SUCCESS"))

    incidents = correlate_alerts(_logs(events))
    assert incidents.empty


def test_different_source_ips_are_not_correlated() -> None:
    events = [_event(i, source_ip="10.0.0.10", event_id=f"IP1_{i}") for i in range(5)]
    events.append(_event(5.5, source_ip="10.0.0.11", event_type="AUTH_SUCCESS", event_id="S1"))

    incidents = correlate_alerts(_logs(events))
    assert incidents.empty


def test_failed_logins_without_subsequent_success_do_not_create_incident() -> None:
    events = [_event(i, event_id=f"N{i}") for i in range(5)]
    incidents = correlate_alerts(_logs(events))
    assert incidents.empty


def test_events_outside_correlation_window_do_not_create_incident() -> None:
    events = [_event(i, event_id=f"W{i}") for i in range(5)]
    events.append(_event(31, event_type="AUTH_SUCCESS", event_id="W_SUCCESS"))
    incidents = correlate_alerts(_logs(events), time_window=timedelta(minutes=15))
    assert incidents.empty


def test_empty_input_returns_empty_incident_schema() -> None:
    incidents = correlate_alerts(pd.DataFrame(columns=REQUIRED_COLUMNS))
    assert incidents.empty
    assert list(incidents.columns) == INCIDENT_COLUMNS


def test_invalid_or_missing_timestamps_are_skipped_safely() -> None:
    events = [_event(i, event_id=f"T{i}") for i in range(5)]
    events.append(_event(7, event_type="AUTH_SUCCESS", event_id="T_SUCCESS"))
    events.append(_event(8, event_id="BAD_TS", timestamp="not-a-timestamp"))
    logs = _logs(events)
    logs.loc[logs["event_id"] == "BAD_TS", "timestamp"] = pd.NaT

    incidents = correlate_alerts(logs)
    assert len(incidents) == 1


def test_unsorted_events_are_handled_in_chronological_order() -> None:
    events = [
        _event(3, event_id="U3"),
        _event(0, event_id="U0"),
        _event(2, event_id="U2"),
        _event(1, event_id="U1"),
        _event(4, event_id="U4"),
        _event(5, event_type="AUTH_SUCCESS", event_id="U_SUCCESS"),
    ]
    incidents = correlate_alerts(_logs(events))
    assert len(incidents) == 1
    assert incidents.iloc[0]["related_events"] == ["U0", "U1", "U2", "U3", "U4", "U_SUCCESS"]


def test_duplicate_incident_prevention() -> None:
    events = [_event(i, event_id=f"D{i}") for i in range(5)]
    events += [
        _event(5.5, event_type="AUTH_SUCCESS", event_id="D_SUCCESS"),
        _event(5.5, event_type="AUTH_SUCCESS", event_id="D_SUCCESS"),
    ]
    incidents = correlate_alerts(_logs(events))
    assert len(incidents) == 1


def test_correlate_events_uses_detection_alerts_for_valid_success_sequence() -> None:
    events = [_event(i, event_id=f"A{i}") for i in range(5)]
    events.append(_event(5.5, event_type="AUTH_SUCCESS", event_id="A_SUCCESS"))
    logs = _logs(events)
    alerts = detect_excessive_auth_failures(logs)

    incidents = correlate_events(logs, alerts)

    assert len(incidents) == 1
    incident = incidents.iloc[0]
    assert incident["incident_type"] == "possible_brute_force_attack"
    assert incident["username"] == "jdoe"
    assert incident["source_ip"] == "10.0.0.50"
    assert set(incident["related_events"]) == {"A0", "A1", "A2", "A3", "A4", "A_SUCCESS"}


def test_correlate_events_no_follow_up_success_creates_no_incident() -> None:
    events = [_event(i, event_id=f"B{i}") for i in range(5)]
    logs = _logs(events)
    alerts = detect_excessive_auth_failures(logs)

    incidents = correlate_events(logs, alerts)
    assert incidents.empty


def test_correlate_events_unrelated_success_creates_no_incident() -> None:
    events = [_event(i, username="alice", event_id=f"C{i}") for i in range(5)]
    events.append(_event(5.5, username="bob", event_type="AUTH_SUCCESS", event_id="C_SUCCESS"))
    logs = _logs(events)
    alerts = detect_excessive_auth_failures(logs)

    incidents = correlate_events(logs, alerts)
    assert incidents.empty


def test_correlate_events_empty_alerts_create_no_incidents() -> None:
    logs = _logs([_event(i, event_id=f"E{i}") for i in range(5)])
    incidents = correlate_events(logs, pd.DataFrame(columns=ALERT_COLUMNS))
    assert incidents.empty


def test_correlate_events_duplicate_success_rows_do_not_duplicate_incidents() -> None:
    events = [_event(i, event_id=f"D{i}") for i in range(5)]
    events += [
        _event(5.5, event_type="AUTH_SUCCESS", event_id="D_SUCCESS"),
        _event(5.5, event_type="AUTH_SUCCESS", event_id="D_SUCCESS"),
    ]
    logs = _logs(events)
    alerts = detect_excessive_auth_failures(logs)

    incidents = correlate_events(logs, alerts)
    assert len(incidents) == 1

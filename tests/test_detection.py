from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest

from src.detection import (
    ALERT_COLUMNS,
    ALERT_STATUS,
    ALERT_TYPE,
    FAILURE_THRESHOLD,
    TIME_WINDOW,
    detect_excessive_auth_failures,
    empty_alert_frame,
)
from src.load_logs import REQUIRED_COLUMNS, load_logs

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
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
        delta = timedelta(minutes=minutes)
        ts = BASE_TIME + delta
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


def test_five_failures_within_five_minutes_creates_alert() -> None:
    logs = _logs([_event(i, event_id=f"E{i}") for i in range(FAILURE_THRESHOLD)])
    alerts = detect_excessive_auth_failures(logs)
    assert len(alerts) == 1
    alert = alerts.iloc[0]
    assert alert["alert_type"] == ALERT_TYPE
    assert alert["status"] == ALERT_STATUS
    assert alert["username"] == "jdoe"
    assert alert["source_ip"] == "10.0.0.50"
    assert alert["hostname"] == "WS-JDOE"
    assert alert["failed_attempts"] == 5
    assert alert["time_window"] == "5 minutes"
    assert alert["event_ids"] == ["E0", "E1", "E2", "E3", "E4"]
    assert "within five minutes" in alert["reason"]
    assert alert["status"] != "confirmed_attack"


def test_inclusive_boundary_exactly_five_minutes_apart() -> None:
    events = [
        _event(0, event_id="B0"),
        _event(1.25, event_id="B1"),
        _event(2.5, event_id="B2"),
        _event(3.75, event_id="B3"),
        _event(5.0, event_id="B4"),
    ]
    alerts = detect_excessive_auth_failures(_logs(events))
    assert len(alerts) == 1
    span = alerts.iloc[0]["last_event_time"] - alerts.iloc[0]["first_event_time"]
    assert span == TIME_WINDOW


def test_four_failures_within_five_minutes_no_alert() -> None:
    logs = _logs([_event(i, event_id=f"F{i}") for i in range(4)])
    alerts = detect_excessive_auth_failures(logs)
    assert alerts.empty
    assert list(alerts.columns) == ALERT_COLUMNS


def test_five_failures_outside_any_five_minute_window_no_alert() -> None:
    logs = _logs([_event(i * 6, event_id=f"S{i}") for i in range(5)])
    alerts = detect_excessive_auth_failures(logs)
    assert alerts.empty


def test_same_username_different_source_ips_no_alert() -> None:
    logs = _logs(
        [
            _event(i, source_ip=f"10.0.0.{60 + i}", event_id=f"IP{i}")
            for i in range(5)
        ]
    )
    alerts = detect_excessive_auth_failures(logs)
    assert alerts.empty


def test_same_source_ip_different_usernames_no_alert() -> None:
    users = ["alice", "bob", "carol", "dave", "erin"]
    logs = _logs(
        [
            _event(i, username=user, source_ip="10.0.0.90", event_id=f"U{i}")
            for i, user in enumerate(users)
        ]
    )
    alerts = detect_excessive_auth_failures(logs)
    assert alerts.empty


def test_invalid_timestamps_are_skipped_without_crash() -> None:
    events = [_event(i, event_id=f"T{i}") for i in range(4)]
    events.append(
        _event(
            4,
            event_id="TBAD",
            timestamp="not-a-timestamp",
        )
    )
    logs = _logs(events)
    assert logs["timestamp"].isna().sum() == 1
    alerts = detect_excessive_auth_failures(logs)
    assert alerts.empty


def test_missing_timestamp_rows_do_not_create_alerts() -> None:
    events = [_event(i, event_id=f"M{i}") for i in range(5)]
    logs = _logs(events)
    logs.loc[0, "timestamp"] = pd.NaT
    alerts = detect_excessive_auth_failures(logs)
    assert alerts.empty


def test_empty_dataset_returns_empty_alert_schema() -> None:
    alerts = detect_excessive_auth_failures(pd.DataFrame(columns=REQUIRED_COLUMNS))
    expected = empty_alert_frame()
    assert alerts.empty
    assert list(alerts.columns) == list(expected.columns) == ALERT_COLUMNS


def test_success_after_failures_is_not_counted() -> None:
    events = [_event(i, event_id=f"X{i}") for i in range(5)]
    events.append(
        _event(4.5, event_type="AUTH_SUCCESS", event_id="XSUCCESS")
    )
    alerts = detect_excessive_auth_failures(_logs(events))
    assert len(alerts) == 1
    assert alerts.iloc[0]["failed_attempts"] == 5
    assert "XSUCCESS" not in alerts.iloc[0]["event_ids"]


def test_duplicate_event_ids_count_once() -> None:
    events = [_event(i, event_id=f"D{i}") for i in range(4)]
    events.append(_event(4, event_id="D3"))  # duplicate of the fourth failure
    alerts = detect_excessive_auth_failures(_logs(events))
    assert alerts.empty


def test_exact_duplicate_rows_without_event_id_count_once() -> None:
    row = _event(0, event_id=None)
    row["event_id"] = pd.NA
    events = []
    for minute in range(5):
        clone = dict(row)
        clone["timestamp"] = BASE_TIME + timedelta(minutes=minute)
        events.append(clone)
        events.append(dict(clone))
    alerts = detect_excessive_auth_failures(_logs(events))
    assert len(alerts) == 1
    assert alerts.iloc[0]["failed_attempts"] == 5


def test_overlapping_windows_merge_into_one_alert() -> None:
    logs = _logs([_event(i, event_id=f"O{i}") for i in range(8)])
    alerts = detect_excessive_auth_failures(logs)
    assert len(alerts) == 1
    assert alerts.iloc[0]["failed_attempts"] == 8
    assert len(alerts.iloc[0]["event_ids"]) == 8


def test_separated_bursts_create_two_alerts() -> None:
    first = [_event(i, event_id=f"A{i}") for i in range(5)]
    second = [_event(20 + i, event_id=f"C{i}") for i in range(5)]
    alerts = detect_excessive_auth_failures(_logs(first + second))
    assert len(alerts) == 2
    assert alerts.iloc[0]["alert_id"] != alerts.iloc[1]["alert_id"]


def test_alert_ids_are_deterministic() -> None:
    logs = _logs([_event(i, event_id=f"Z{i}") for i in range(5)])
    first = detect_excessive_auth_failures(logs)
    second = detect_excessive_auth_failures(logs)
    assert first.iloc[0]["alert_id"] == second.iloc[0]["alert_id"]
    assert str(first.iloc[0]["alert_id"]).startswith("alert_")


def test_missing_username_or_source_ip_skipped() -> None:
    events = [_event(i, event_id=f"N{i}") for i in range(5)]
    logs = _logs(events)
    logs.loc[:, "username"] = pd.NA
    assert detect_excessive_auth_failures(logs).empty
    logs = _logs(events)
    logs.loc[:, "source_ip"] = pd.NA
    assert detect_excessive_auth_failures(logs).empty


def test_missing_detection_columns_raise() -> None:
    with pytest.raises(ValueError, match="columns are missing"):
        detect_excessive_auth_failures(pd.DataFrame({"timestamp": []}))


def test_synthetic_dataset_contains_one_qualifying_burst() -> None:
    logs = load_logs(DATA_DIR / "security_logs.csv")
    alerts = detect_excessive_auth_failures(logs)
    assert len(alerts) == 1
    assert alerts.iloc[0]["username"] == "jdoe"
    assert alerts.iloc[0]["source_ip"] == "10.0.0.50"
    assert alerts.iloc[0]["failed_attempts"] == 5

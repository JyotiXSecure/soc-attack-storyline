from pathlib import Path

import pandas as pd
import pytest

from src.load_logs import (
    REQUIRED_COLUMNS,
    LogLoadError,
    empty_log_frame,
    load_logs,
)

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


def _write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    lines = [",".join(header)]
    for row in rows:
        lines.append(",".join(row))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _sample_row(**overrides: str) -> list[str]:
    values = {
        "timestamp": "2026-01-15 10:00:00",
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.10",
        "username": "jdoe",
        "hostname": "WS-JDOE",
        "event_type": "AUTH_FAILURE",
        "event_id": "EVT-1",
        "process": "winlogon.exe",
        "command": "",
        "domain": "corp.example",
        "destination_port": "445",
        "file_name": "",
        "file_path": "",
        "action": "login",
        "status": "failure",
        "bytes": "0",
    }
    values.update(overrides)
    return [values[column] for column in REQUIRED_COLUMNS]


def test_load_project_synthetic_csv() -> None:
    frame = load_logs(DATA_DIR / "security_logs.csv")
    assert list(frame.columns) == REQUIRED_COLUMNS
    assert len(frame) > 0
    assert pd.api.types.is_datetime64_any_dtype(frame["timestamp"])
    assert frame["timestamp"].dt.tz is None


def test_header_only_csv_returns_empty_schema(tmp_path: Path) -> None:
    path = tmp_path / "empty_rows.csv"
    path.write_text(",".join(REQUIRED_COLUMNS) + "\n", encoding="utf-8")
    frame = load_logs(path)
    assert frame.empty
    assert list(frame.columns) == REQUIRED_COLUMNS


def test_completely_empty_file_raises(tmp_path: Path) -> None:
    path = tmp_path / "blank.csv"
    path.write_text("", encoding="utf-8")
    with pytest.raises(LogLoadError, match="empty"):
        load_logs(path)


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(LogLoadError, match="not found"):
        load_logs(tmp_path / "missing.csv")


def test_missing_columns_raise(tmp_path: Path) -> None:
    path = tmp_path / "partial.csv"
    path.write_text("timestamp,username\n2026-01-15 10:00:00,jdoe\n", encoding="utf-8")
    with pytest.raises(LogLoadError, match="missing required columns"):
        load_logs(path)


def test_invalid_timestamp_becomes_nat(tmp_path: Path) -> None:
    path = tmp_path / "bad_ts.csv"
    _write_csv(
        path,
        REQUIRED_COLUMNS,
        [
            _sample_row(timestamp="not-a-date", event_id="EVT-BAD"),
            _sample_row(timestamp="2026-01-15 10:00:00", event_id="EVT-OK"),
        ],
    )
    frame = load_logs(path)
    assert pd.isna(frame.loc[0, "timestamp"])
    assert frame.loc[1, "timestamp"] == pd.Timestamp("2026-01-15 10:00:00")


def test_blank_optional_fields_become_missing(tmp_path: Path) -> None:
    path = tmp_path / "blanks.csv"
    _write_csv(path, REQUIRED_COLUMNS, [_sample_row(hostname="", command="n/a")])
    frame = load_logs(path)
    assert pd.isna(frame.loc[0, "hostname"])
    assert pd.isna(frame.loc[0, "command"])


def test_timezone_aware_timestamp_converted_to_naive_utc(tmp_path: Path) -> None:
    path = tmp_path / "tz.csv"
    _write_csv(
        path,
        REQUIRED_COLUMNS,
        [_sample_row(timestamp="2026-01-15T10:00:00+00:00")],
    )
    frame = load_logs(path)
    assert frame.loc[0, "timestamp"] == pd.Timestamp("2026-01-15 10:00:00")
    assert frame["timestamp"].dt.tz is None


def test_empty_log_frame_schema() -> None:
    frame = empty_log_frame()
    assert frame.empty
    assert list(frame.columns) == REQUIRED_COLUMNS

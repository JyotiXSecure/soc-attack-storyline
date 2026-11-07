"""Load and validate synthetic security logs from CSV.

Expected timestamp format
-------------------------
Preferred value: ``YYYY-MM-DD HH:MM:SS`` (example: ``2026-01-15 10:00:00``).

Timezone policy
---------------
All timestamps are treated as UTC.

* Naive values (no timezone) are assumed to already be UTC.
* Timezone-aware values are converted to UTC.
* After conversion, timestamps are stored as timezone-naive pandas datetimes
  that still represent UTC. This avoids mixing aware and naive types later.

Invalid timestamps become ``NaT``. They do not crash loading. Detection
modules must skip ``NaT`` rows and must not invent event times.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

REQUIRED_COLUMNS: list[str] = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "username",
    "hostname",
    "event_type",
    "event_id",
    "process",
    "command",
    "domain",
    "destination_port",
    "file_name",
    "file_path",
    "action",
    "status",
    "bytes",
]

EMPTY_STRING_TOKENS = {"", "nan", "none", "null", "n/a", "na"}


class LogLoadError(ValueError):
    """Raised when a log file cannot be used for investigation."""


def _blank_to_na(value: object) -> object:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return pd.NA
    text = str(value).strip()
    if text.lower() in EMPTY_STRING_TOKENS:
        return pd.NA
    return text


def _parse_timestamps(raw: pd.Series) -> pd.Series:
    """Parse timestamps as UTC, then store them as naive UTC datetimes."""
    parsed = pd.to_datetime(raw, errors="coerce", utc=True, format="mixed")
    # utc=True yields timezone-aware UTC (or NaT). Strip tz so the rest of
    # the project compares naive UTC timestamps only.
    return parsed.dt.tz_convert("UTC").dt.tz_localize(None)


def empty_log_frame() -> pd.DataFrame:
    """Return a zero-row frame with the required schema."""
    return pd.DataFrame({column: pd.Series(dtype="object") for column in REQUIRED_COLUMNS})


def load_logs(csv_path: str | Path) -> pd.DataFrame:
    """Load a synthetic security-log CSV and return a validated DataFrame.

    Raises
    ------
    LogLoadError
        If the path is missing, the file is empty with no header, required
        columns are absent, or pandas cannot parse the CSV structure.
    """
    path = Path(csv_path)
    if not path.exists():
        raise LogLoadError(f"Log file not found: {path}")
    if path.is_dir():
        raise LogLoadError(f"Expected a CSV file, found a directory: {path}")
    if path.stat().st_size == 0:
        raise LogLoadError(
            f"Log file is empty and has no header row: {path}. "
            "A valid file must include the required column names."
        )

    try:
        frame = pd.read_csv(path, dtype=str, keep_default_na=True)
    except pd.errors.EmptyDataError as exc:
        raise LogLoadError(
            f"Log file has no parsable CSV content: {path}"
        ) from exc
    except pd.errors.ParserError as exc:
        raise LogLoadError(f"Log file is not valid CSV: {path}") from exc

    missing = [column for column in REQUIRED_COLUMNS if column not in frame.columns]
    extra_note = ""
    if missing:
        raise LogLoadError(
            "Log file is missing required columns: "
            + ", ".join(missing)
            + extra_note
            + ". Expected columns: "
            + ", ".join(REQUIRED_COLUMNS)
        )

    if frame.empty:
        empty = empty_log_frame()
        empty["timestamp"] = pd.Series(dtype="datetime64[ns]")
        return empty

    cleaned = frame.loc[:, REQUIRED_COLUMNS].copy()
    for column in REQUIRED_COLUMNS:
        if column == "timestamp":
            continue
        cleaned[column] = cleaned[column].map(_blank_to_na)

    cleaned["timestamp"] = _parse_timestamps(cleaned["timestamp"])
    return cleaned.reset_index(drop=True)

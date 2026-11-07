from __future__ import annotations

from datetime import timedelta
import hashlib

import pandas as pd

FAILURE_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=5)
TIME_WINDOW_LABEL = "5 minutes"
ALERT_TYPE = "excessive_authentication_failures"
ALERT_STATUS = "needs_investigation"
AUTH_FAILURE_EVENT_TYPE = "AUTH_FAILURE"

ALERT_COLUMNS: list[str] = [
    "alert_id",
    "alert_type",
    "timestamp",
    "username",
    "source_ip",
    "hostname",
    "failed_attempts",
    "time_window",
    "first_event_time",
    "last_event_time",
    "event_ids",
    "status",
    "reason",
]


def empty_alert_frame() -> pd.DataFrame:
    """Return a zero-row alert table with the required output schema."""
    data: dict[str, pd.Series] = {}
    for column in ALERT_COLUMNS:
        if column in {"timestamp", "first_event_time", "last_event_time"}:
            data[column] = pd.Series(dtype="datetime64[ns]")
        elif column == "failed_attempts":
            data[column] = pd.Series(dtype="int64")
        elif column == "event_ids":
            data[column] = pd.Series(dtype="object")
        else:
            data[column] = pd.Series(dtype="object")
    return pd.DataFrame(data)


def _missing_required_columns(frame: pd.DataFrame) -> list[str]:
    needed = [
        "timestamp",
        "source_ip",
        "username",
        "hostname",
        "event_type",
        "event_id",
    ]
    return [column for column in needed if column not in frame.columns]


def _deduplicate_events(frame: pd.DataFrame) -> pd.DataFrame:
    """Apply the documented duplicate-event policy."""
    if frame.empty:
        return frame

    has_event_id = frame["event_id"].notna()
    with_ids = frame.loc[has_event_id].drop_duplicates(subset=["event_id"], keep="first")
    without_ids = frame.loc[~has_event_id].drop_duplicates(keep="first")
    combined = pd.concat([with_ids, without_ids], ignore_index=True)
    return combined.sort_values("timestamp", kind="mergesort").reset_index(drop=True)


def _prepare_failures(logs: pd.DataFrame) -> pd.DataFrame:
    failures = logs.loc[logs["event_type"] == AUTH_FAILURE_EVENT_TYPE].copy()
    if failures.empty:
        return failures

    failures = failures.loc[failures["timestamp"].notna()]
    failures = failures.loc[failures["username"].notna()]
    failures = failures.loc[failures["source_ip"].notna()]
    if failures.empty:
        return failures

    failures["username"] = failures["username"].astype(str).str.strip()
    failures["source_ip"] = failures["source_ip"].astype(str).str.strip()
    failures = failures.loc[failures["username"] != ""]
    failures = failures.loc[failures["source_ip"] != ""]
    return _deduplicate_events(failures)


def _merge_qualifying_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not ranges:
        return []
    merged: list[list[int]] = [list(ranges[0])]
    for start, end in ranges[1:]:
        last = merged[-1]
        if start <= last[1]:
            last[1] = max(last[1], end)
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]


def _qualifying_clusters(timestamps: pd.Series) -> list[tuple[int, int]]:
    """Return merged inclusive index ranges that meet the rolling threshold."""
    n = len(timestamps)
    if n < FAILURE_THRESHOLD:
        return []

    qualifying: list[tuple[int, int]] = []
    left = 0
    for right in range(n):
        while timestamps.iloc[right] - timestamps.iloc[left] > TIME_WINDOW:
            left += 1
        if right - left + 1 >= FAILURE_THRESHOLD:
            qualifying.append((left, right))
    return _merge_qualifying_ranges(qualifying)


def _hostname_from_cluster(cluster: pd.DataFrame) -> object:
    values = cluster["hostname"].dropna().astype(str).str.strip()
    values = values.loc[values != ""]
    unique = sorted(set(values.tolist()))
    if not unique:
        return pd.NA
    if len(unique) == 1:
        return unique[0]
    # Multiple hostnames were present in the evidence; report them rather
    # than picking one and hiding the rest.
    return ", ".join(unique)


def _alert_id(
    username: str,
    source_ip: str,
    first_event_time: pd.Timestamp,
    last_event_time: pd.Timestamp,
    event_ids: list[str],
) -> str:
    payload = "|".join(
        [
            ALERT_TYPE,
            username,
            source_ip,
            first_event_time.isoformat(),
            last_event_time.isoformat(),
            ",".join(event_ids),
        ]
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"alert_{digest}"


def _cluster_reason(failed_attempts: int, span: timedelta) -> str:
    if span <= TIME_WINDOW:
        return (
            f"{failed_attempts} authentication failures for the same username "
            "and source IP occurred within five minutes."
        )
    return (
        f"{failed_attempts} authentication failures for the same username "
        "and source IP formed a contiguous cluster of overlapping five-minute "
        "windows that each met the failure threshold."
    )


def _alert_from_cluster(cluster: pd.DataFrame) -> dict:
    cluster = cluster.sort_values("timestamp", kind="mergesort")
    first_event_time = cluster["timestamp"].iloc[0]
    last_event_time = cluster["timestamp"].iloc[-1]
    username = str(cluster["username"].iloc[0])
    source_ip = str(cluster["source_ip"].iloc[0])

    event_ids: list[str] = []
    for value in cluster["event_id"].tolist():
        if pd.isna(value):
            continue
        text = str(value).strip()
        if text:
            event_ids.append(text)

    failed_attempts = int(len(cluster))
    reason = _cluster_reason(failed_attempts, last_event_time - first_event_time)
    return {
        "alert_id": _alert_id(
            username, source_ip, first_event_time, last_event_time, event_ids
        ),
        "alert_type": ALERT_TYPE,
        "timestamp": last_event_time,
        "username": username,
        "source_ip": source_ip,
        "hostname": _hostname_from_cluster(cluster),
        "failed_attempts": failed_attempts,
        "time_window": TIME_WINDOW_LABEL,
        "first_event_time": first_event_time,
        "last_event_time": last_event_time,
        "event_ids": event_ids,
        "status": ALERT_STATUS,
        "reason": reason,
    }


def detect_excessive_auth_failures(logs: pd.DataFrame) -> pd.DataFrame:
    """Return investigation alerts for excessive authentication failures.

    Parameters
    ----------
    logs:
        A DataFrame produced by ``load_logs`` (or an equivalent frame that
        includes the required columns). An empty frame yields an empty alert
        table with ``ALERT_COLUMNS``.
    """
    if logs is None:
        raise TypeError("logs must be a pandas DataFrame, not None")
    if not isinstance(logs, pd.DataFrame):
        raise TypeError(f"logs must be a pandas DataFrame, got {type(logs).__name__}")

    missing = _missing_required_columns(logs)
    if missing:
        raise ValueError(
            "Cannot run excessive-authentication detection because these "
            "columns are missing: " + ", ".join(missing)
        )

    if logs.empty:
        return empty_alert_frame()

    failures = _prepare_failures(logs)
    if failures.empty:
        return empty_alert_frame()

    alerts: list[dict] = []
    grouped = failures.groupby(["username", "source_ip"], dropna=True, sort=False)
    for _, group in grouped:
        group = group.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
        clusters = _qualifying_clusters(group["timestamp"])
        for start, end in clusters:
            alerts.append(_alert_from_cluster(group.iloc[start : end + 1]))

    if not alerts:
        return empty_alert_frame()
    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pandas as pd

from src.detection import detect_excessive_auth_failures
from src.load_logs import REQUIRED_COLUMNS, load_logs

CORRELATION_WINDOW = timedelta(minutes=15)
CORRELATION_WINDOW_LABEL = "15 minutes"
AUTH_FAILURE_EVENT_TYPE = "AUTH_FAILURE"
AUTH_SUCCESS_EVENT_TYPE = "AUTH_SUCCESS"
INCIDENT_TYPE = "possible_brute_force_attack"
INCIDENT_STATUS = "needs_investigation"

INCIDENT_COLUMNS: list[str] = [
    "incident_type",
    "username",
    "source_ip",
    "first_seen",
    "last_seen",
    "related_events",
    "status",
]

# Legacy output schema kept for compatibility with the older evidence-based
# correlation API already present in this project.
CORRELATED_COLUMNS: list[str] = list(REQUIRED_COLUMNS) + [
    "alert_id",
    "matched_signals",
    "correlation_reason",
]


def empty_incident_frame() -> pd.DataFrame:
    """Return a zero-row incident table with the incident schema."""
    return pd.DataFrame({column: pd.Series(dtype="object") for column in INCIDENT_COLUMNS})


def empty_correlation_frame() -> pd.DataFrame:
    """Return a zero-row correlation table for legacy compatibility."""
    data: dict[str, pd.Series] = {}
    for column in CORRELATED_COLUMNS:
        if column == "timestamp":
            data[column] = pd.Series(dtype="datetime64[ns]")
        elif column == "matched_signals":
            data[column] = pd.Series(dtype="object")
        else:
            data[column] = pd.Series(dtype="object")
    return pd.DataFrame(data)


def _clean_text(value: object) -> str | None:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    if value is pd.NA or pd.isna(value):
        return None
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null", "n/a", "na"}:
        return None
    return text


def _as_naive_utc(series: pd.Series) -> pd.Series:
    parsed = pd.to_datetime(series, errors="coerce", utc=True, format="mixed")
    return parsed.dt.tz_convert("UTC").dt.tz_localize(None)


def _deduplicate_events(frame: pd.DataFrame) -> pd.DataFrame:
    if frame.empty:
        return frame
    has_event_id = frame["event_id"].notna()
    with_ids = frame.loc[has_event_id].drop_duplicates(subset=["event_id"], keep="first")
    without_ids = frame.loc[~has_event_id].drop_duplicates(keep="first")
    combined = pd.concat([with_ids, without_ids], ignore_index=True)
    return combined.sort_values("timestamp", kind="mergesort").reset_index(drop=True)


def _event_ids(rows: list[pd.Series]) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    for row in rows:
        event_id = _clean_text(row.get("event_id"))
        if event_id is None:
            continue
        if event_id not in seen:
            ids.append(event_id)
            seen.add(event_id)
    return ids


def _missing_columns(frame: pd.DataFrame, required: list[str]) -> list[str]:
    return [column for column in required if column not in frame.columns]


def correlate_alerts(
    logs: pd.DataFrame,
    *,
    time_window: timedelta = CORRELATION_WINDOW,
) -> pd.DataFrame:
    """Identify a brute-force pattern: repeated failures followed by success.

    Parameters
    ----------
    logs:
        Security logs from ``load_logs`` (or a compatible DataFrame).
    time_window:
        Max time between the last failed login and the subsequent successful
        login for the same username and source IP.
    """
    if logs is None:
        raise TypeError("logs must be a pandas DataFrame, not None")
    if not isinstance(logs, pd.DataFrame):
        raise TypeError(f"logs must be a pandas DataFrame, got {type(logs).__name__}")

    missing = _missing_columns(logs, REQUIRED_COLUMNS)
    if missing:
        raise ValueError(
            "Cannot correlate alerts because these columns are missing: "
            + ", ".join(missing)
        )

    if logs.empty:
        return empty_incident_frame()

    prepared = logs.loc[:, REQUIRED_COLUMNS].copy()
    prepared["timestamp"] = _as_naive_utc(prepared["timestamp"])
    prepared = prepared.loc[prepared["timestamp"].notna()].copy()

    prepared["username"] = prepared["username"].map(_clean_text)
    prepared["source_ip"] = prepared["source_ip"].map(_clean_text)
    prepared = prepared.loc[
        prepared["username"].notna() & prepared["source_ip"].notna()
    ].copy()
    prepared = prepared.loc[
        prepared["event_type"].isin({AUTH_FAILURE_EVENT_TYPE, AUTH_SUCCESS_EVENT_TYPE})
    ].copy()
    prepared = _deduplicate_events(prepared)
    prepared = prepared.sort_values("timestamp", kind="mergesort").reset_index(drop=True)

    incidents: list[dict] = []
    group_signature_seen: set[tuple[str, str, pd.Timestamp, pd.Timestamp]] = set()

    for _, group in prepared.groupby(["username", "source_ip"], dropna=True, sort=False):
        failures: list[pd.Series] = []
        first_failure: pd.Timestamp | None = None
        last_failure: pd.Timestamp | None = None

        for _, row in group.iterrows():
            event_type = _clean_text(row.get("event_type"))
            if event_type is None:
                continue

            ts = row["timestamp"]
            if pd.isna(ts):
                continue

            if event_type == AUTH_FAILURE_EVENT_TYPE:
                failures.append(row)
                if first_failure is None:
                    first_failure = ts
                last_failure = ts
                continue

            if event_type != AUTH_SUCCESS_EVENT_TYPE or not failures or last_failure is None:
                continue

            if ts <= last_failure:
                continue

            if ts - last_failure > time_window:
                failures.clear()
                first_failure = None
                last_failure = None
                continue

            if len(failures) < 5:
                failures.clear()
                first_failure = None
                last_failure = None
                continue

            success_id = _clean_text(row.get("event_id"))
            related_events = _event_ids(failures)
            if success_id:
                related_events.append(success_id)

            signature = (
                row["username"],
                row["source_ip"],
                first_failure,
                last_failure,
            )
            if signature not in group_signature_seen:
                incidents.append(
                    {
                        "incident_type": INCIDENT_TYPE,
                        "username": row["username"],
                        "source_ip": row["source_ip"],
                        "first_seen": first_failure,
                        "last_seen": ts,
                        "related_events": related_events,
                        "status": INCIDENT_STATUS,
                    }
                )
                group_signature_seen.add(signature)

            failures.clear()
            first_failure = None
            last_failure = None

    if not incidents:
        return empty_incident_frame()

    result = pd.DataFrame(incidents, columns=INCIDENT_COLUMNS)
    return result.sort_values(["first_seen", "source_ip", "username"], kind="mergesort").reset_index(drop=True)


def correlate_events(logs: pd.DataFrame, alerts: pd.DataFrame) -> pd.DataFrame:
    """Create incidents from existing detection alerts and the raw log stream.

    Every alert from ``detect_excessive_auth_failures`` is treated as an
    investigation anchor. We look for a later ``AUTH_SUCCESS`` event in the raw
    log stream for the same username and source IP that occurs within the active
    correlation window. This keeps the logic tied to the detection output rather
    than rediscovering alerts from scratch.
    """
    if logs is None or alerts is None:
        raise TypeError("logs and alerts must be pandas DataFrames, not None")
    if not isinstance(logs, pd.DataFrame):
        raise TypeError(f"logs must be a pandas DataFrame, got {type(logs).__name__}")
    if not isinstance(alerts, pd.DataFrame):
        raise TypeError(f"alerts must be a pandas DataFrame, got {type(alerts).__name__}")

    missing_logs = _missing_columns(logs, REQUIRED_COLUMNS)
    if missing_logs:
        raise ValueError(
            "Cannot correlate events because these log columns are missing: "
            + ", ".join(missing_logs)
        )
    alert_required = ["alert_id", "username", "source_ip", "last_event_time", "event_ids"]
    missing_alerts = _missing_columns(alerts, alert_required)
    if missing_alerts:
        raise ValueError(
            "Cannot correlate events because these alert columns are missing: "
            + ", ".join(missing_alerts)
        )

    if logs.empty or alerts.empty:
        return empty_incident_frame()

    prepared_logs = logs.loc[:, REQUIRED_COLUMNS].copy()
    prepared_logs["timestamp"] = _as_naive_utc(prepared_logs["timestamp"])
    prepared_logs = prepared_logs.loc[prepared_logs["timestamp"].notna()].copy()
    prepared_logs["username"] = prepared_logs["username"].map(_clean_text)
    prepared_logs["source_ip"] = prepared_logs["source_ip"].map(_clean_text)
    prepared_logs = prepared_logs.loc[
        prepared_logs["username"].notna() & prepared_logs["source_ip"].notna()
    ].copy()
    prepared_logs = prepared_logs.sort_values("timestamp", kind="mergesort").reset_index(drop=True)

    incidents: list[dict] = []
    seen_signatures: set[tuple[str, str, pd.Timestamp, pd.Timestamp]] = set()

    for _, alert_row in alerts.iterrows():
        username = _clean_text(alert_row.get("username"))
        source_ip = _clean_text(alert_row.get("source_ip"))
        if username is None or source_ip is None:
            continue

        last_failure = alert_row.get("last_event_time")
        if pd.isna(last_failure) if isinstance(last_failure, float) else False:
            continue
        if pd.isna(last_failure):
            continue

        alert_ids = set()
        alert_event_ids = alert_row.get("event_ids")
        if isinstance(alert_event_ids, str):
            alert_ids = {part.strip() for part in alert_event_ids.split(",") if part.strip()}
        elif isinstance(alert_event_ids, (list, tuple, set)):
            for item in alert_event_ids:
                text = _clean_text(item)
                if text is not None:
                    alert_ids.add(text)

        window_end = pd.Timestamp(last_failure) + CORRELATION_WINDOW
        window = prepared_logs.loc[
            (prepared_logs["timestamp"] > pd.Timestamp(last_failure))
            & (prepared_logs["timestamp"] <= window_end)
            & (prepared_logs["username"] == username)
            & (prepared_logs["source_ip"] == source_ip)
        ].copy()

        success_candidates = window.loc[
            window["event_type"].astype(str).str.upper() == AUTH_SUCCESS_EVENT_TYPE
        ].copy()
        if success_candidates.empty:
            continue

        for _, success_row in success_candidates.iterrows():
            success_id = _clean_text(success_row.get("event_id"))
            if success_id is not None and success_id in alert_ids:
                continue

            signature = (
                username,
                source_ip,
                pd.Timestamp(last_failure),
                success_row["timestamp"],
            )
            if signature in seen_signatures:
                continue

            related_events = list(alert_ids)
            if success_id is not None:
                related_events.append(success_id)
            seen_signatures.add(signature)
            incidents.append(
                {
                    "incident_type": INCIDENT_TYPE,
                    "username": username,
                    "source_ip": source_ip,
                    "first_seen": pd.Timestamp(last_failure),
                    "last_seen": success_row["timestamp"],
                    "related_events": related_events,
                    "status": INCIDENT_STATUS,
                }
            )
            break

    if not incidents:
        return empty_incident_frame()

    result = pd.DataFrame(incidents, columns=INCIDENT_COLUMNS)
    return result.sort_values(["first_seen", "source_ip", "username"], kind="mergesort").reset_index(drop=True)


def generate_incident_report(
    csv_path: str | Path = "data/security_logs.csv",
    *,
    output_path: str | Path = "output/incidents.csv",
) -> pd.DataFrame:
    """Load logs, detect alerts, correlate follow-up success, and save a CSV report."""
    logs = load_logs(csv_path)
    alerts = detect_excessive_auth_failures(logs)
    incidents = correlate_events(logs, alerts)

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    if incidents.empty:
        report = pd.DataFrame(columns=INCIDENT_COLUMNS)
    else:
        report = incidents.copy()

    report.to_csv(destination, index=False)
    return report


if __name__ == "__main__":
    generate_incident_report()

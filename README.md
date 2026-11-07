# SOC Attack Storyline Analyzer

## Overview
A Python-based SOC investigation project that analyzes synthetic security logs to detect and correlate suspicious authentication activity.

## Key Features
- Loads and validates CSV security log data
- Detects repeated failed authentication attempts
- Correlates failed login bursts with a later successful login from the same user and IP
- Produces a simple incident CSV report

## Technologies Used
- Python
- pandas
- pytest

## Project Structure
```text
soc-attack-storyline/
├── README.md
├── requirements.txt
├── data/
│   └── security_logs.csv
├── output/
│   └── incidents.csv
├── src/
│   ├── load_logs.py
│   ├── detection.py
│   └── correlation.py
├── tests/
│   ├── test_load_logs.py
│   ├── test_detection.py
│   └── test_correlation.py
```

## Installation and Execution
```powershell
cd soc-attack-storyline
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -v
python -c "from src.correlation import generate_incident_report; generate_incident_report()"
```

## Detection and Correlation
The detection logic identifies repeated `AUTH_FAILURE` events for the same user and source IP within a short time window. The correlation layer then checks whether a matching `AUTH_SUCCESS` event follows, creating a possible brute-force incident record.

## Sample Incident Output
```csv
incident_type,username,source_ip,first_seen,last_seen,related_events,status
possible_brute_force_attack,jdoe,10.0.0.50,2026-01-15 10:00:00,2026-01-15 10:05:30,"['F0','F1','F2','F3','F4','S1']",needs_investigation
```

## Current Limitation
Only brute-force authentication detection is implemented in this version; broader attack correlation and advanced SOC analytics are not included yet.

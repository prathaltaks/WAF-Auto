# WAF-Auto — Haltdos WAF Testing Platform

Purpose: lightweight UI and engine for running Haltdos WAF checks and attack suites locally.

Quick start

1. Create a Python virtualenv and activate it:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Run the server:

```powershell
python server.py
```

Common helpers

- `manage.py` — small utility to list or clean old `reports/` files and to run the server from the virtualenv.
- `run_server.ps1` / `run_server.sh` — convenience scripts for Windows/macOS-Linux.

Notes

- `server_debug.log` is ignored via `.gitignore` to avoid noisy commits.
- If you want me to further refactor the code into a package (move files under `src/`, add unit tests, simplify APIs), tell me and I will propose a plan.

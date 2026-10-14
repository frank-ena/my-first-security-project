# Port Scanner

A small Flask app that checks a fixed set of TCP ports on an authorized target.
Scans are restricted to localhost and private-network addresses. The scan
endpoint requires a secret access token.

## Run locally

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:SCAN_ACCESS_TOKEN = "replace-with-a-long-random-secret"
python app.py
```

Open <http://127.0.0.1:5000> and enter the configured access token in the form.
Do not commit the token or put it in the HTML or source code.

## Run tests

```powershell
python -m unittest discover -s . -p "test_*.py" -v
```

## Deploy on Render from GitHub

1. Push this project to a GitHub repository.
2. In Render, choose **New + → Blueprint**, select the repository, and apply
   the `render.yaml` blueprint.
3. Render generates `SCAN_ACCESS_TOKEN` as a secret environment variable. Find
   it in the service's Environment settings and provide it to authorized users
   through a secure channel. Never commit or publish the token.
4. Wait for the service to finish deploying, then open its `onrender.com`
   URL and enter the token to scan.

The app scans from the Render service, not from your browser. It cannot reach
your computer's localhost or home LAN unless that network is explicitly
connected to the hosting service. Targets must resolve only to localhost or
private-network addresses. Use this tool only on systems you own or have
permission to test.

## Scope and limitations

The app scans TCP ports 21, 22, 23, 25, 53, 80, 110, 443, 3306, and 8080. Each
connection has a one-second timeout. It does not scan arbitrary public IPs,
UDP ports, custom port ranges, or networks inaccessible from the hosting
service.

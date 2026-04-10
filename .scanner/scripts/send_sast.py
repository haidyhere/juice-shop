import json
import os
import sys
import urllib.request
import urllib.error

# Load SAST result
with open("sast-result.json", "r", encoding="utf-8") as f:
    scan_data = json.load(f)

# Extract findings
results = scan_data.get("results", [])

severity_counts = {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
}

top_findings = []

for r in results:
    if not isinstance(r, dict):
        continue

    severity = r.get("extra", {}).get("severity", "").lower()

    if severity in severity_counts:
        severity_counts[severity] += 1

    top_findings.append({
        "message": r.get("extra", {}).get("message", ""),
        "severity": severity,
        "file": r.get("path", ""),
        "line": r.get("start", {}).get("line", 0),
    })

total_findings = len(results)

# Risk score
risk_score = (
    severity_counts["critical"] * 10 +
    severity_counts["high"] * 7 +
    severity_counts["medium"] * 4 +
    severity_counts["low"] * 1
)

# Payload
payload = {
    "repo": os.environ.get("GITHUB_REPOSITORY", "unknown"),
    "runId": os.environ.get("GITHUB_RUN_ID", "unknown"),
    "commitSha": os.environ.get("GITHUB_SHA", "unknown"),
    "branch": os.environ.get("GITHUB_REF_NAME", "unknown"),
    "triggeredBy": os.environ.get("GITHUB_ACTOR", "unknown"),
    "scanType": "sast",
    "reportS3Key": os.environ.get("S3_KEY", ""),
    "result": {
        "riskScore": risk_score,
        "severityCounts": severity_counts,
        "totalFindings": total_findings,
        "topFindings": top_findings[:5],
    },
}

# Send request
token = os.environ["INGEST_TOKEN_SAST"]
base_url = os.environ["BACKEND_API_URL"].rstrip("/")
url = f"{base_url}/ingest/sast"

body = json.dumps(payload).encode("utf-8")

req = urllib.request.Request(
    url,
    data=body,
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    },
    method="POST",
)

try:
    with urllib.request.urlopen(req, timeout=15) as resp:
        print(f"API ingest succeeded: HTTP {resp.status}")
except urllib.error.HTTPError as e:
    print(f"API ingest failed: HTTP {e.code} - {e.read().decode()}")
    sys.exit(1)
except urllib.error.URLError as e:
    print(f"WARNING: Could not reach backend API ({e.reason}). Skipping ingest.")
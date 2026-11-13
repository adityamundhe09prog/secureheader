import json
from html import escape

def build_report(scan: dict, analysis: dict) -> dict:
    return {
        "tool": "SecureHeader",
        "version": "1.0.0",
        "scan": {
            "requested_url": scan["requested_url"],
            "final_url": scan["final_url"],
            "status_code": scan["status_code"],
        },
        "summary": {
            "score": analysis["score"],
            "present": analysis["present_count"],
            "total": analysis["total_count"],
        },
        "checks": analysis["checks"],
    }

def save_json(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)

def save_html(report: dict, path: str) -> None:
    rows = []
    for item in report["checks"]:
        status = "Present" if item["present"] else "Missing"
        recommendation = item["recommendation"] or "No action suggested by this check."
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                escape(item["header"]), status, escape(item["severity"]),
                escape(recommendation)
            )
        )
    html = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>SecureHeader report</title>
<style>body{font:16px system-ui;margin:2rem auto;max-width:1000px;padding:0 1rem;color:#182230}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #d8dee8;padding:10px;text-align:left}
th{background:#f1f5f9}.score{font-size:2rem;font-weight:700}</style></head>
<body><h1>SecureHeader report</h1>
<p><b>Target:</b> {target}</p><p><b>HTTP status:</b> {status}</p>
<p class="score">Header presence score: {score}/100</p>
<table><thead><tr><th>Header</th><th>Status</th><th>Severity</th><th>Recommendation</th></tr></thead>
<tbody>{rows}</tbody></table>
<p><small>This report checks header presence only. It does not validate policy quality or prove a site is secure.</small></p>
</body></html>""".format(
        target=escape(report["scan"]["final_url"]),
        status=report["scan"]["status_code"],
        score=report["summary"]["score"],
        rows="".join(rows),
    )
    with open(path, "w", encoding="utf-8") as file:
        file.write(html)

#!/usr/bin/env python3
"""Turn a cppcheck XML report into HTML, and gate on error-severity findings.

Replaces the CI step that ran:

    xsltproc /usr/share/cppcheck/cppcheck-htmlreport.xslt ...

That XSLT has not shipped with cppcheck for years. The step failed on every
run with "failed to load external entity", which failed the whole analysis
job — so the job could only ever fail for a cosmetic reason, and never for
an actual finding.

Usage:
    python3 scripts/cppcheck_report.py <report.xml> [--html out.html]
                                       [--fail-on error|warning|style|none]

Exit status is 0 unless findings at or above --fail-on are present
(default: error). Severity order: error > warning > portability >
performance > style > information.
"""
import argparse
import html
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

# Most severe first. A --fail-on of "warning" also fails on "error".
SEVERITY_ORDER = [
    "error", "warning", "portability", "performance", "style", "information",
]

SEVERITY_COLOUR = {
    "error":       "#b3261e",
    "warning":     "#a15c00",
    "portability": "#5b5bd6",
    "performance": "#5b5bd6",
    "style":       "#5f6368",
    "information": "#5f6368",
}


def parse(path):
    """Return a list of findings. Tolerates a report with no errors block.

    Uses the stdlib parser rather than defusedxml so CI needs no extra
    package. xml.etree is safe against external entity expansion, but not
    against entity-expansion denial of service ("billion laughs"), so the
    input is rejected outright if it declares a DTD or any entity. A
    cppcheck report never contains either, and refusing beats expanding.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(2)

    lowered = text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        print(f"error: {path} declares a DTD or entity; refusing to parse",
              file=sys.stderr)
        sys.exit(2)

    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        print(f"error: cannot parse {path}: {exc}", file=sys.stderr)
        sys.exit(2)

    findings = []
    for err in root.iter("error"):
        locs = [
            {
                "file": loc.get("file", ""),
                "line": loc.get("line", "0"),
                "info": loc.get("info", ""),
            }
            for loc in err.findall("location")
        ]
        findings.append({
            "id":       err.get("id", ""),
            "severity": err.get("severity", "information"),
            "msg":      err.get("msg", ""),
            "verbose":  err.get("verbose", ""),
            "cwe":      err.get("cwe", ""),
            "locations": locs,
        })
    return findings


def render_html(findings, title):
    by_sev = Counter(f["severity"] for f in findings)
    by_file = defaultdict(list)
    for f in findings:
        key = f["locations"][0]["file"] if f["locations"] else "(no file)"
        by_file[key].append(f)

    rows = []
    for sev in SEVERITY_ORDER:
        if by_sev.get(sev):
            rows.append(
                f'<tr><td style="color:{SEVERITY_COLOUR[sev]}">'
                f"<strong>{sev}</strong></td><td>{by_sev[sev]}</td></tr>"
            )
    summary = "".join(rows) or '<tr><td colspan="2">No findings</td></tr>'

    blocks = []
    for path in sorted(by_file):
        items = []
        for f in sorted(by_file[path],
                        key=lambda x: SEVERITY_ORDER.index(x["severity"])
                        if x["severity"] in SEVERITY_ORDER else 99):
            line = f["locations"][0]["line"] if f["locations"] else "0"
            colour = SEVERITY_COLOUR.get(f["severity"], "#5f6368")
            cwe = f' CWE-{html.escape(f["cwe"])}' if f["cwe"] else ""
            items.append(
                f'<li><span style="color:{colour}"><strong>'
                f'{html.escape(f["severity"])}</strong></span> '
                f'line {html.escape(line)} '
                f'<code>{html.escape(f["id"])}</code>{cwe}<br>'
                f'{html.escape(f["msg"])}</li>'
            )
        blocks.append(
            f"<h3>{html.escape(path)} "
            f'<span style="font-weight:normal;color:#5f6368">'
            f"({len(by_file[path])})</span></h3><ul>{''.join(items)}</ul>"
        )

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.5; }}
 table {{ border-collapse: collapse; margin-bottom: 2rem; }}
 td, th {{ border: 1px solid #ddd; padding: 0.3rem 0.8rem; text-align: left; }}
 code {{ background: #f2f2f2; padding: 0 0.25rem; }}
 h3 {{ margin-bottom: 0.25rem; }}
 ul {{ margin-top: 0.25rem; }}
</style></head><body>
<h1>{html.escape(title)}</h1>
<p>{len(findings)} finding(s) across {len(by_file)} file(s).</p>
<table><tr><th>Severity</th><th>Count</th></tr>{summary}</table>
{''.join(blocks)}
</body></html>
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("xml", help="cppcheck XML report (--xml --xml-version=2)")
    ap.add_argument("--html", help="write an HTML report to this path")
    ap.add_argument("--title", default="LughOS Cppcheck Report")
    ap.add_argument("--fail-on", default="error",
                    choices=SEVERITY_ORDER + ["none"],
                    help="exit non-zero when a finding at or above this "
                         "severity is present (default: error)")
    args = ap.parse_args()

    findings = parse(args.xml)
    by_sev = Counter(f["severity"] for f in findings)

    print(f"cppcheck: {len(findings)} finding(s)")
    for sev in SEVERITY_ORDER:
        if by_sev.get(sev):
            print(f"  {sev:12} {by_sev[sev]}")

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(findings, args.title))
        print(f"HTML report written to {args.html}")

    if args.fail_on == "none":
        return 0

    threshold = SEVERITY_ORDER.index(args.fail_on)
    blocking = [f for f in findings
                if f["severity"] in SEVERITY_ORDER
                and SEVERITY_ORDER.index(f["severity"]) <= threshold]

    if blocking:
        print(f"\nFAIL: {len(blocking)} finding(s) at or above '{args.fail_on}':",
              file=sys.stderr)
        for f in blocking:
            loc = f["locations"][0] if f["locations"] else {"file": "?", "line": "0"}
            print(f"  {loc['file']}:{loc['line']}  [{f['severity']}] "
                  f"{f['id']}: {f['msg']}", file=sys.stderr)
        return 1

    print(f"\nOK: no findings at or above '{args.fail_on}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())

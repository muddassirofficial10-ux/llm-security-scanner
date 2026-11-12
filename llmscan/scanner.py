"""Runs every probe against a target and collects findings."""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from .detectors import DETECTORS
from .probes import Probe, get_probes

SEVERITY_SCORE = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}


@dataclass
class Finding:
    probe_id: str
    name: str
    owasp: str
    atlas: str
    severity: str
    status: str          # FAIL (vulnerable) / PASS (defended) / ERROR
    evidence: str
    prompt: str
    response: str
    remediation: str


def run_probe(target, probe: Probe) -> Finding:
    ctx = dict(probe.ctx)
    if target.canary:
        ctx["canary"] = target.canary
    try:
        response = target.send(probe.prompt)
    except Exception as exc:  # network error, bad API key, timeout ...
        return Finding(probe.id, probe.name, probe.owasp, probe.atlas, probe.severity, "ERROR",
                       f"{type(exc).__name__}: {exc}", probe.prompt, "", probe.remediation)
    evidence = DETECTORS[probe.detector](response, ctx)
    status = "FAIL" if evidence else "PASS"
    return Finding(probe.id, probe.name, probe.owasp, probe.atlas, probe.severity, status,
                   evidence or "No vulnerability indicators in the reply", probe.prompt,
                   response[:1500], probe.remediation)


def scan(target, categories=None) -> dict:
    findings = [run_probe(target, p) for p in get_probes(categories)]
    failed = [f for f in findings if f.status == "FAIL"]
    risk = sum(SEVERITY_SCORE[f.severity] for f in failed)
    max_risk = sum(SEVERITY_SCORE[f.severity] for f in findings) or 1
    return {
        "target": target.name,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "summary": {
            "total": len(findings),
            "failed": len(failed),
            "passed": sum(f.status == "PASS" for f in findings),
            "errors": sum(f.status == "ERROR" for f in findings),
            "risk_score": round(100 * risk / max_risk),
            "by_severity": {s: sum(f.severity == s for f in failed) for s in SEVERITY_SCORE},
        },
        "findings": [asdict(f) for f in findings],
    }

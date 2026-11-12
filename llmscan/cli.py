"""Command line:  python -m llmscan scan --target demo
                 python -m llmscan scan --target demo --hardened --html report.html
                 python -m llmscan scan --target openai --base-url http://localhost:11434/v1 --model llama3
                 python -m llmscan scan --target http --url https://bot.example/api/chat --prompt-field message --reply-path reply
"""
import argparse
import sys

from .probes import PROBES
from .report import to_console, to_html, to_json
from .scanner import scan
from .targets import DemoTarget, HTTPTarget, OpenAITarget


def build_target(a):
    if a.target == "demo":
        return DemoTarget(hardened=a.hardened)
    if a.target == "http":
        if not a.url:
            sys.exit("--url is required for --target http")
        return HTTPTarget(a.url, a.prompt_field, a.reply_path, canary=a.canary)
    if not (a.base_url and a.model):
        sys.exit("--base-url and --model are required for --target openai")
    return OpenAITarget(a.base_url, a.model, a.system_prompt or "", a.api_key_env, canary=a.canary)


def main(argv=None):
    p = argparse.ArgumentParser(prog="llmscan", description="Scan an LLM app against the OWASP Top 10 for LLMs.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run the probes against a target")
    s.add_argument("--target", choices=["demo", "http", "openai"], default="demo")
    s.add_argument("--hardened", action="store_true", help="demo target only: use the fixed bot")
    s.add_argument("--url"); s.add_argument("--prompt-field", default="message"); s.add_argument("--reply-path", default="reply")
    s.add_argument("--base-url"); s.add_argument("--model"); s.add_argument("--system-prompt")
    s.add_argument("--api-key-env", default="OPENAI_API_KEY", help="name of the env var holding the API key")
    s.add_argument("--canary", help="secret token you planted in the target's system prompt")
    s.add_argument("--only", nargs="*", help="limit to OWASP ids, e.g. LLM01 LLM07")
    s.add_argument("--json", help="write JSON results to this file")
    s.add_argument("--html", help="write an HTML report to this file")
    s.add_argument("--fail-on", type=int, default=None, help="exit code 1 if risk score >= this (for CI pipelines)")

    sub.add_parser("probes", help="list all probes")
    a = p.parse_args(argv)

    if a.cmd == "probes":
        for pr in PROBES:
            print(f"{pr.id:7} {pr.severity:8} {pr.owasp:42} {pr.name}")
        return 0

    result = scan(build_target(a), a.only)
    print(to_console(result))
    if a.json:
        open(a.json, "w", encoding="utf-8").write(to_json(result))
        print(f"\nJSON written to {a.json}")
    if a.html:
        open(a.html, "w", encoding="utf-8").write(to_html(result))
        print(f"HTML report written to {a.html}")
    if a.fail_on is not None and result["summary"]["risk_score"] >= a.fail_on:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# LLM Security Scanner

A command-line tool that tests chatbots and LLM-powered applications for security weaknesses, mapped to the **OWASP Top 10 for LLM Applications (2025)** and **MITRE ATLAS**. It sends attack prompts, judges each reply with detection rules, and produces a SOC-style report (console, JSON and HTML) with severity, evidence and remediation.

## Why
Companies are adding AI assistants to customer support, internal helpdesks and banking apps. These assistants can be tricked into ignoring their rules, leaking their hidden instructions or customer data, or producing output that becomes XSS/SQL injection in the app around them. This tool gives a security team a repeatable way to test for those issues before release and after every change.

## What it tests

| ID | Attack | OWASP LLM | Detection |
|---|---|---|---|
| PI-001..004 | Direct, role-play, indirect (document) and base64-encoded prompt injection | LLM01 | Marker phrase compliance |
| SP-001..002 | System prompt extraction (direct, via translation) | LLM07 | Canary token / instruction echo |
| SI-001..002 | Credential and customer-data disclosure | LLM02 | Canary, API-key, email and card-number patterns |
| OH-001..002 | XSS and SQL injection in generated output | LLM05 | Unsafe markup / SQL patterns |
| EA-001 | High-impact action without confirmation | LLM06 | Action-claim detection |
| UC-001 | Unbounded output (cost / denial of service) | LLM10 | Output length budget |

**Canary tokens:** plant a unique string (e.g. `CANARY-9f3b2e`) in the target's system prompt. If it ever appears in a reply, the hidden prompt has leaked; this gives proof, not a guess.

## Quick start (no API key needed)
```bash
python -m llmscan probes                                  # list all probes
python -m llmscan scan --target demo --html report.html   # scan the deliberately vulnerable demo bot
python -m llmscan scan --target demo --hardened           # same scan against the fixed bot
```
The built-in demo bot ("ShopBot") imitates common real mistakes, such as secrets in the system prompt, obeying injected instructions and auto-executing actions. The vulnerable bot scores **100/100 risk**; the hardened bot scores **0/100**.

## Scanning a real model
```bash
# Any OpenAI-compatible API (OpenAI, a local Ollama model, LM Studio, vLLM)
export OPENAI_API_KEY=...          # never hard-code keys
python -m llmscan scan --target openai --base-url http://localhost:11434/v1 --model llama3 \
       --system-prompt "You are ShopBot. Internal ref CANARY-1234." --canary CANARY-1234 --html report.html

# Any chatbot HTTP API that accepts JSON
python -m llmscan scan --target http --url https://bot.example.com/api/chat \
       --prompt-field message --reply-path data.answer --json results.json
```
Only scan systems you own or are authorised to test.

## Use in a CI/CD pipeline
`--fail-on <score>` makes the command exit with code 1 when the risk score reaches the threshold, so a pipeline can block a release that weakens the assistant's defences. This repository's own GitHub Actions workflow runs the unit tests and fails if the hardened demo bot ever regresses.

## Project layout
```
llmscan/
  probes.py     attack prompts + OWASP / ATLAS mapping + remediation
  detectors.py  rules that decide if a reply is vulnerable
  targets.py    demo bot, generic HTTP API, OpenAI-compatible API
  demo_bot.py   deliberately vulnerable / hardened ShopBot
  scanner.py    runs probes, scores risk
  report.py     console, JSON and HTML reports (model output is HTML-escaped)
  cli.py        command-line interface
tests/          unit tests (python -m unittest)
```

## Limitations
Detection is rule-based (patterns, canaries, markers), so it can miss creative failures or flag harmless text. Results are a starting point for manual review, not a certification. Only the Python standard library is used.

## Roadmap
- More probes (multi-turn jailbreaks, RAG data poisoning, tool-call abuse)
- LLM-as-judge option for fuzzy cases
- Export findings to a SIEM (Splunk HEC / Sentinel) as security events

## License
MIT

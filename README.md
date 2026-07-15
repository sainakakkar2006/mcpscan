# MCPScan

A security scanner for **MCP (Model Context Protocol) servers** and AI-agent tool configurations.

Point it at an MCP manifest (a `.json` file, an endpoint URL, or an inline dict) and it produces:

- an **inventory** of every tool the agent can access (name, description, permissions),
- a list of **security findings** (severity + detail + fix),
- a single deterministic **risk score** (0–100 + low/medium/high band).

Built on the architecture of [secret-scanner-cli](https://github.com/sainakakkar2006/secret-scanner-cli): the same declarative detector pattern, and the secret-detection regexes + `mask_secret` are reused directly for the exfiltration check.

## Why

An MCP server publishes a manifest: a list of tools, each with a name, a natural-language description, and an input schema. The agent's LLM **reads the descriptions as instructions** — so the manifest itself is the attack surface. A malicious or compromised server can inject instructions into a description ("tool poisoning"), request far broader access than its purpose needs, or pair sensitive-data access with a network sink to exfiltrate secrets.

## Install

```bash
pip install .            # CLI only, stdlib-only core
pip install ".[api]"     # + FastAPI service
pip install ".[llm]"     # + LLM tool-poisoning classifier
```

## Usage

```bash
mcpscan scan examples/clean_manifest.json
mcpscan scan examples/poisoned_manifest.json --format md --out report.md
mcpscan scan https://mcp.example.com/manifest.json --format json
```

Exit code is non-zero when any HIGH finding exists (for CI), unless `--no-fail`.

```
$ mcpscan scan examples/poisoned_manifest.json
Server: githb
Risk score: 100/100 (high)
Tools: 3
...
read_file [HIGH] tool_poisoning
  detail: description contains agent-directed instruction: 'Ignore all previous instructions'
  fix: Remove agent-directed instructions, hidden Unicode, and encoded payloads from tool
       descriptions; descriptions should only describe what the tool does.
```

## The checks

| # | Check | Severity | What it catches |
|---|---|---|---|
| 1 | `tool_poisoning` | HIGH | Descriptions containing agent-directed instructions, hidden/invisible Unicode, decodable base64 payloads. Optional `--llm` classifier improves recall. |
| 2 | `broad_scope` | HIGH | Wildcard permissions, shell/exec parameters, root-filesystem defaults, env-var access beyond the stated purpose. |
| 3 | `exfiltration_path` | HIGH | A sensitive source (env/files/secrets — detected with Secret Scanner's regexes) paired with an external sink (arbitrary URL/webhook). |
| 4 | `missing_auth` | MEDIUM | No declared authentication/scoped consent, or unencrypted (http://) transport. |
| 5 | `supply_chain` | MEDIUM | Unpinned versions, unknown publishers, names typosquatting popular servers. |
| 6 | `shadow_tools` | HIGH | *(planned, dynamic)* Live server exposes tools not in its manifest or makes unexpected network calls. |

## Output contract

```json
{
  "risk_score": 100,
  "band": "high",
  "total_findings": 16,
  "inventory": [ { "name": "...", "description": "...", "schema": {}, "permissions": [] } ],
  "findings": [ { "tool": "...", "check": "...", "severity": "...", "detail": "...", "remediation": "..." } ]
}
```

Scoring is deterministic: HIGH = 35, MEDIUM = 15, LOW = 5, capped at 100. The band follows the worst severity present.

## API

```bash
pip install ".[api]"
uvicorn mcpscan.api:app
curl -X POST localhost:8000/scan -H 'content-type: application/json' -d @examples/poisoned_manifest.json
```

## Benchmark

`examples/benchmark/` is a small labeled corpus: each manifest is tagged in `labels.json` with the `(tool, check)` pairs a scanner should report.

```bash
PYTHONPATH=src python3 scripts/benchmark.py
```

## Tests

```bash
python -m unittest discover -s tests
```

## Responsible disclosure

MCPScan is for **defensive auditing**. Scan only manifests and endpoints you own, operate, or are authorized to test. If you find an issue in a third-party server: report it privately to the maintainer, give them time to fix it, and never exploit it. The example manifests in this repo are synthetic — no real secrets, no live third-party scanning in the tests.

## License

MIT

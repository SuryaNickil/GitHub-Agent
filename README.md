<p align="center">
  <img src="https://img.shields.io/badge/AI--Powered-Security%20Scanner-7c5cfc?style=for-the-badge&logo=shield&logoColor=white" alt="SecScan Agent" />
  <img src="https://img.shields.io/badge/LangGraph-Agentic%20Pipeline-00e676?style=for-the-badge&logo=graphql&logoColor=white" alt="LangGraph" />
  <img src="https://img.shields.io/badge/Python-3.14+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
</p>

# SecScan Agent

**An autonomous, AI-powered repository security scanner built on a multi-agent architecture.**

SecScan Agent combines static analysis, pattern matching, and large language model reasoning into a single automated pipeline that scans any Git repository for security vulnerabilities — then helps your team understand, triage, and fix them.

---

## The Problem

Security vulnerabilities in source code are the #1 attack vector for modern software breaches. Traditional scanning tools produce noisy, context-free reports that overwhelm developers and get ignored. Teams lack the bandwidth to manually review every finding, prioritize remediation, and track fixes across sprints.

**The result:** Critical vulnerabilities ship to production.

## The Solution

SecScan Agent is an **intelligent security agent** that doesn't just find vulnerabilities — it understands them, explains them, and fixes them.

```
   Git Repo URL
       |
       v
  +-----------+
  | Clone Repo|
  +-----+-----+
        |
   Fan-out (parallel)
   /    |    \
  v     v     v
+------+ +-------+ +---------+
|Bandit| |Pattern| |AI Review|    <-- 3 independent scanners
|SAST  | | Match | | (Claude)|        run simultaneously
+------+ +-------+ +---------+
   \    |    /
    v   v   v
  +-----------+
  | Classify  |    <-- Merge, deduplicate, rank by severity
  +-----------+
       |
       v
  Dashboard / CLI / Jira / Auto-Fix
```

---

## Key Features

### Multi-Agent Scanning Pipeline
Three specialized scanners run **in parallel** using LangGraph's fan-out/fan-in architecture:

| Scanner | Method | What It Catches |
|---------|--------|-----------------|
| **Bandit SAST** | Static analysis | Python-specific security anti-patterns, CWE-mapped issues |
| **Pattern Engine** | 17 regex signatures | Hardcoded secrets, API keys, AWS credentials, SQL injection, XSS, command injection, insecure deserialization |
| **AI Code Review** | Claude Sonnet 4.6 | Business logic flaws, auth bypass, cryptographic weaknesses, context-dependent vulnerabilities that rules can't catch |

Results are merged, deduplicated, and severity-ranked into a unified report.

### Interactive Web Dashboard
A real-time dark/light themed dashboard with:
- **One-click scanning** of any public or private Git repository
- **Severity breakdown** with visual indicators (Critical / High / Medium / Low)
- **Per-vulnerability drill-down** with AI-powered explanations, impact analysis, and code fix suggestions
- **AI Chat Assistant** to ask questions about findings in natural language
- **Source attribution** showing which scanner detected each issue

### Jira Integration
Seamless issue tracking integration:
- **Bulk ticket creation** for all critical/high vulnerabilities with a single click
- **Auto-populated fields**: severity-mapped priority, security labels, detailed descriptions with fix guidance
- **Sprint assignment**: Tickets land in the active sprint (To Do), not the backlog

### AI Auto-Fix Agent
The most powerful feature — an autonomous remediation pipeline:
1. Fetches open security tickets from Jira
2. Clones the target repository
3. Uses AI to generate fixes for each CRITICAL and HIGH vulnerability
4. Commits all fixes to a new branch
5. Pushes and opens a Pull Request automatically

**Zero manual intervention from detection to PR.**

---

## Architecture

```
repo-security-scanner/
  main.py                  # CLI entry point (serve / scan)
  scanner/
    __init__.py
    graph.py               # LangGraph agent pipeline + integrations
    dashboard.py           # Flask web dashboard (single-file SPA)
  pyproject.toml           # Dependencies & project metadata
```

### Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Agent Framework** | LangGraph (StateGraph) | Orchestrates parallel scanner agents with fan-out/fan-in |
| **AI Models** | Claude Sonnet 4.6 | Deep code review during scan |
| | Claude Haiku 4.5 | Chat assistant, vulnerability inspection, auto-fix generation |
| **Static Analysis** | Bandit | Python SAST with CWE mapping |
| **Web Framework** | Flask | Dashboard API and SPA serving |
| **Issue Tracking** | Jira REST API v2/v3 | Ticket creation, sprint assignment, bulk operations |
| **Version Control** | Git / GitHub CLI | Repo cloning, auto-fix branch management, PR creation |
| **Language** | Python 3.14+ | Core runtime |

### LangGraph State Machine

The scanner is built as a compiled LangGraph `StateGraph` with typed state:

```python
class ScanState(TypedDict, total=False):
    repo_url: str
    repo_path: str
    cloned: bool
    bandit_results: Annotated[list[Vulnerability], _merge_vulns]
    pattern_results: Annotated[list[Vulnerability], _merge_vulns]
    ai_results: Annotated[list[Vulnerability], _merge_vulns]
    vulnerabilities: list[Vulnerability]
    summary: dict
    agent_trace: Annotated[list[str], add]
```

The `Annotated` reducers enable parallel node execution — each scanner writes to its own channel, and the `classify` node merges them.

---

## Getting Started

### Prerequisites

- Python 3.14+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- Git
- GitHub CLI (`gh`) — for auto-fix PR creation

### Installation

```bash
# Clone
git clone https://github.com/SuryaNickil/GitHub-Agent.git
cd GitHub-Agent

# Install dependencies
uv sync
```

### Configuration

Set environment variables:

```bash
# Required — AI-powered scanning and chat
export ANTHROPIC_API_KEY="sk-ant-..."

# Optional — Jira integration
export JIRA_BASE_URL="https://your-org.atlassian.net"
export JIRA_EMAIL="you@company.com"
export JIRA_API_TOKEN="your-jira-api-token"
export JIRA_PROJECT_KEY="SEC"
```

### Usage

#### Web Dashboard
```bash
python main.py serve --port 5000
```
Open `http://127.0.0.1:5000` in your browser.

#### CLI Scan
```bash
# Human-readable output
python main.py scan https://github.com/owner/repo

# JSON output for CI/CD pipelines
python main.py scan https://github.com/owner/repo --json
```

---

## How It Works

### 1. Scan Pipeline (30-60 seconds)

```
User enters repo URL
    --> Clone (shallow, depth=1)
    --> Fan-out to 3 parallel agents:
        [Bandit]   Static analysis on Python files
        [Pattern]  17 regex signatures across 25+ file types
        [AI]       Claude reviews high-priority files (auth, config, crypto, etc.)
    --> Fan-in: Classify node merges, deduplicates, and sorts by severity
    --> Results rendered in dashboard
```

### 2. Vulnerability Inspection

Click any vulnerability to get an AI-generated deep-dive:
- **Root cause explanation** — why this code is vulnerable
- **Impact assessment** — what an attacker could achieve
- **Step-by-step fix guide** — actionable remediation
- **Before/after code** — copy-paste ready fix
- **Prevention tips** — how to avoid this class of issue

### 3. Jira Ticket Creation

One click creates tickets for all critical vulnerabilities:
- Summary: `[CRITICAL] Hardcoded Secret/Password`
- Priority: Mapped from severity (Critical -> Highest, High -> High, etc.)
- Labels: `security`, `secscan`, `critical`
- Description: Full vulnerability details + AI-generated fix guidance
- Sprint: Automatically assigned to the active sprint

### 4. Auto-Fix Agent

The auto-fix pipeline runs autonomously:
```
Fetch Jira security tickets
    --> Filter CRITICAL + HIGH
    --> Clone target repo
    --> For each vulnerability:
        AI generates complete fixed file
        Write fix to disk
    --> git checkout -b autofix/security-vulnerabilities
    --> git commit + push
    --> gh pr create with detailed changelist
```

---

## Pattern Detection Coverage

The pattern engine scans **25+ file types** for:

| Category | Patterns | Severity |
|----------|----------|----------|
| Hardcoded credentials | Passwords, secrets, API keys | CRITICAL |
| Cloud credentials | AWS access keys, private keys | CRITICAL |
| Embedded keys | PEM private keys in source | CRITICAL |
| Token exposure | Bearer tokens, auth tokens | HIGH |
| Injection risks | `eval()`, `exec()`, `system()`, `popen()` | HIGH |
| SQL injection | String concatenation in SQL queries | HIGH |
| Insecure deserialization | `pickle.loads()` | HIGH |
| Permission issues | `chmod 777` | HIGH |
| XSS vectors | `innerHTML`, `document.write()` | MEDIUM |
| Unsafe parsing | `yaml.load()` without SafeLoader | MEDIUM |
| SSL bypass | `verify=False` | MEDIUM |
| CORS misconfiguration | Wildcard `*` origins | MEDIUM |
| Network exposure | Binding to `0.0.0.0` | LOW |

---

## Dashboard Preview

The dashboard features a modern, glassmorphism-inspired design with:

- **Dark/Light theme** toggle with smooth transitions
- **Real-time scan progress** with animated loading states
- **Severity-coded cards** with visual hierarchy
- **Expandable vulnerability details** with syntax-highlighted code
- **Integrated AI chat** panel for conversational analysis
- **Bulk action bar** for Jira ticket creation
- **Auto-fix panel** showing fix progress and PR links

---

## CI/CD Integration

Use the CLI mode in your pipeline:

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    python main.py scan ${{ github.server_url }}/${{ github.repository }} --json > scan-results.json

- name: Check for critical issues
  run: |
    CRITICAL=$(cat scan-results.json | jq '.summary.critical')
    if [ "$CRITICAL" -gt "0" ]; then
      echo "CRITICAL vulnerabilities found!"
      exit 1
    fi
```

---

## Roadmap

- [ ] GitHub Actions integration (scan on every PR)
- [ ] Slack/Teams notifications for critical findings
- [ ] Historical scan comparison and trend analysis
- [ ] SBOM generation and dependency vulnerability scanning
- [ ] Custom pattern rule configuration via YAML
- [ ] Multi-repo batch scanning
- [ ] Role-based access control for the dashboard
- [ ] Webhook support for external integrations

---

## License

MIT

---

<p align="center">
  <b>Built with LangGraph + Claude + Flask</b><br/>
  <sub>Autonomous security scanning, from detection to pull request.</sub>
</p>

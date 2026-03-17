"""
LangGraph-based security vulnerability scanner agent.

Agent pipeline (fan-out / fan-in):
  1. clone_repo       – clone / validate the git repo
  2. run_bandit     ─┐
  3. pattern_scan   ─┼─ run in PARALLEL (independent scanners)
  4. ai_review      ─┘
  5. classify         – merge, deduplicate, assign severity

Additional features:
  - chat_with_agent  – Gemini-powered chat for discussing findings
  - inspect_issue    – deep-dive analysis + fix suggestions via Gemini
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from operator import add
from typing import Annotated, TypedDict

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage
import requests as http_requests
from langgraph.graph import END, StateGraph

# ── State ────────────────────────────────────────────────────────────────────

class Vulnerability(TypedDict, total=False):
    id: str
    file: str
    line: int
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    confidence: str        # HIGH / MEDIUM / LOW
    title: str
    description: str
    source: str            # bandit / pattern / ai


def _merge_vulns(left: list[Vulnerability], right: list[Vulnerability]) -> list[Vulnerability]:
    return left + right


class ScanState(TypedDict, total=False):
    repo_url: str
    repo_path: str
    cloned: bool
    bandit_results: Annotated[list[Vulnerability], _merge_vulns]
    pattern_results: Annotated[list[Vulnerability], _merge_vulns]
    ai_results: Annotated[list[Vulnerability], _merge_vulns]
    vulnerabilities: list[Vulnerability]
    error: str
    summary: dict
    agent_trace: Annotated[list[str], add]


# ── 1. Clone / validate repo ────────────────────────────────────────────────

def clone_repo(state: ScanState) -> ScanState:
    repo_url = state["repo_url"]

    if os.path.isdir(repo_url):
        return {"repo_path": repo_url, "cloned": False, "agent_trace": ["clone_repo:local"]}

    tmp = tempfile.mkdtemp(prefix="secscanner_")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, tmp],
            check=True, capture_output=True, text=True, timeout=120,
        )
    except subprocess.CalledProcessError as e:
        return {"error": f"Clone failed: {e.stderr}", "agent_trace": ["clone_repo:failed"]}
    return {"repo_path": tmp, "cloned": True, "agent_trace": ["clone_repo:ok"]}


# ── 2. Bandit static analysis ───────────────────────────────────────────────

BANDIT_SEVERITY_MAP = {"LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH"}

def run_bandit(state: ScanState) -> ScanState:
    if state.get("error"):
        return {"bandit_results": [], "agent_trace": ["bandit:skipped"]}
    repo = state["repo_path"]
    try:
        result = subprocess.run(
            ["bandit", "-r", repo, "-f", "json", "-ll"],
            capture_output=True, text=True, timeout=300,
        )
        stdout = result.stdout.strip()
        if stdout and stdout[0] == '{':
            data = json.loads(stdout)
        else:
            data = {}
    except Exception:
        return {"bandit_results": [], "agent_trace": ["bandit:error"]}

    vulns: list[Vulnerability] = []
    for i, r in enumerate(data.get("results", [])):
        vulns.append(Vulnerability(
            id=f"BAN-{i+1:04d}",
            file=os.path.relpath(r["filename"], repo),
            line=r.get("line_number", 0),
            severity=BANDIT_SEVERITY_MAP.get(r.get("issue_severity", ""), "MEDIUM"),
            confidence=r.get("issue_confidence", "MEDIUM"),
            title=r.get("issue_text", "Unknown issue"),
            description=f"[{r.get('test_id','')}] {r.get('issue_text','')}",
            source="bandit",
        ))
    return {"bandit_results": vulns, "agent_trace": [f"bandit:found_{len(vulns)}"]}


# ── 3. Pattern-based scanning ───────────────────────────────────────────────

SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}', "API Key Exposure", "HIGH"),
    (r'(?i)(secret|password|passwd|pwd)\s*[:=]\s*["\'][^"\']{8,}', "Hardcoded Secret/Password", "CRITICAL"),
    (r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["\']?[A-Za-z0-9/+=]{20,}', "AWS Credential Leak", "CRITICAL"),
    (r'(?i)private[_-]?key\s*[:=]\s*["\']', "Private Key Reference", "HIGH"),
    (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', "Embedded Private Key", "CRITICAL"),
    (r'(?i)(token|bearer)\s*[:=]\s*["\']?[A-Za-z0-9_\-\.]{20,}', "Token Exposure", "HIGH"),
    (r'(?i)eval\s*\(', "Use of eval()", "MEDIUM"),
    (r'(?i)(exec|system|popen|subprocess\.call)\s*\(', "Command Injection Risk", "HIGH"),
    (r'(?i)innerHTML\s*=', "Potential XSS via innerHTML", "MEDIUM"),
    (r'(?i)document\.write\s*\(', "Potential XSS via document.write", "MEDIUM"),
    (r'(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*\+\s*["\']?\s*\+', "Potential SQL Injection", "HIGH"),
    (r'(?i)pickle\.loads?\s*\(', "Insecure Deserialization (pickle)", "HIGH"),
    (r'(?i)yaml\.load\s*\(', "Unsafe YAML Load", "MEDIUM"),
    (r'(?i)verify\s*=\s*False', "SSL Verification Disabled", "MEDIUM"),
    (r'(?i)CORS\(.*origins?\s*=\s*["\']?\*', "Wildcard CORS Policy", "MEDIUM"),
    (r'0\.0\.0\.0', "Binding to All Interfaces", "LOW"),
    (r'(?i)chmod\s+777', "World-writable Permissions", "HIGH"),
]

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".env",
    ".sh", ".bash", ".zsh", ".rs", ".c", ".cpp", ".h", ".cs", ".swift",
}


def pattern_scan(state: ScanState) -> ScanState:
    if state.get("error"):
        return {"pattern_results": [], "agent_trace": ["pattern:skipped"]}
    repo = state["repo_path"]
    vulns: list[Vulnerability] = []
    idx = 0

    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "vendor", "__pycache__")]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SCAN_EXTENSIONS:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                continue
            for lineno, line in enumerate(lines, 1):
                for pattern, title, severity in SECRET_PATTERNS:
                    if re.search(pattern, line):
                        idx += 1
                        vulns.append(Vulnerability(
                            id=f"PAT-{idx:04d}",
                            file=os.path.relpath(fpath, repo),
                            line=lineno,
                            severity=severity,
                            confidence="MEDIUM",
                            title=title,
                            description=f"Pattern matched in: {line.strip()[:120]}",
                            source="pattern",
                        ))
    return {"pattern_results": vulns, "agent_trace": [f"pattern:found_{len(vulns)}"]}


# ── 4. AI-powered review (Anthropic) ────────────────────────────────────────

def _collect_interesting_files(repo: str, max_files: int = 15, max_chars: int = 40000) -> str:
    priority_names = {"auth", "login", "session", "token", "password", "crypt",
                      "secret", "config", "setting", "database", "db", "api",
                      "route", "middleware", "handler", "server", "app"}
    scored: list[tuple[int, str]] = []

    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "vendor", "__pycache__")]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SCAN_EXTENSIONS:
                continue
            fpath = os.path.join(root, fname)
            name_lower = fname.lower()
            score = sum(2 for kw in priority_names if kw in name_lower)
            if ext in (".env", ".cfg", ".ini", ".conf"):
                score += 3
            scored.append((score, fpath))

    scored.sort(key=lambda x: -x[0])
    chunks: list[str] = []
    total = 0
    for _, fpath in scored[:max_files]:
        try:
            with open(fpath, "r", errors="ignore") as f:
                content = f.read(8000)
        except Exception:
            continue
        rel = os.path.relpath(fpath, repo)
        chunk = f"\n### {rel}\n```\n{content}\n```"
        if total + len(chunk) > max_chars:
            break
        chunks.append(chunk)
        total += len(chunk)
    return "\n".join(chunks)


def ai_review(state: ScanState) -> ScanState:
    if state.get("error"):
        return {"ai_results": [], "agent_trace": ["ai:skipped"]}

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return {"ai_results": [], "agent_trace": ["ai:no_key"]}

    repo = state["repo_path"]
    code_context = _collect_interesting_files(repo)

    if not code_context.strip():
        return {"ai_results": [], "agent_trace": ["ai:no_files"]}

    llm = ChatAnthropic(model="claude-sonnet-4-6", temperature=0, max_tokens=4096)

    prompt = f"""You are an expert application security engineer. Analyze the following code files for security vulnerabilities.

Focus on:
- Injection flaws (SQL, command, XSS, etc.)
- Authentication / authorization issues
- Sensitive data exposure
- Security misconfigurations
- Insecure dependencies usage patterns
- Cryptographic weaknesses
- Business logic flaws

For each vulnerability found, respond with a JSON array of objects:
{{
  "file": "relative/path.py",
  "line": 42,
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "title": "Short title",
  "description": "Detailed explanation and remediation advice"
}}

If no vulnerabilities are found, return an empty array: []
Respond ONLY with the JSON array, no other text.

{code_context}"""

    try:
        resp = llm.invoke([HumanMessage(content=prompt)])
        text = resp.content.strip()
        match = re.search(r'\[.*\]', text, re.DOTALL)
        items = json.loads(match.group()) if match else []
    except Exception:
        return {"ai_results": [], "agent_trace": ["ai:error"]}

    vulns: list[Vulnerability] = []
    for i, item in enumerate(items):
        vulns.append(Vulnerability(
            id=f"AI-{i+1:04d}",
            file=item.get("file", "unknown"),
            line=item.get("line", 0),
            severity=item.get("severity", "MEDIUM"),
            confidence="MEDIUM",
            title=item.get("title", "AI-detected issue"),
            description=item.get("description", ""),
            source="ai",
        ))
    return {"ai_results": vulns, "agent_trace": [f"ai:found_{len(vulns)}"]}


# ── 5. Classify & merge ─────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def classify(state: ScanState) -> ScanState:
    all_vulns: list[Vulnerability] = []
    all_vulns.extend(state.get("bandit_results") or [])
    all_vulns.extend(state.get("pattern_results") or [])
    all_vulns.extend(state.get("ai_results") or [])

    seen: set[str] = set()
    deduped: list[Vulnerability] = []
    for v in all_vulns:
        key = f"{v.get('file','')}:{v.get('line',0)}:{v.get('title','')[:30]}"
        if key not in seen:
            seen.add(key)
            deduped.append(v)

    deduped.sort(key=lambda v: SEVERITY_ORDER.get(v.get("severity", "INFO"), 4))

    for i, v in enumerate(deduped):
        v["id"] = f"VULN-{i+1:04d}"

    summary = {
        "total": len(deduped),
        "critical": sum(1 for v in deduped if v.get("severity") == "CRITICAL"),
        "high": sum(1 for v in deduped if v.get("severity") == "HIGH"),
        "medium": sum(1 for v in deduped if v.get("severity") == "MEDIUM"),
        "low": sum(1 for v in deduped if v.get("severity") == "LOW"),
        "info": sum(1 for v in deduped if v.get("severity") == "INFO"),
        "sources": {
            "bandit": len(state.get("bandit_results") or []),
            "pattern": len(state.get("pattern_results") or []),
            "ai": len(state.get("ai_results") or []),
        },
    }

    if state.get("cloned") and state.get("repo_path"):
        shutil.rmtree(state["repo_path"], ignore_errors=True)

    return {"vulnerabilities": deduped, "summary": summary, "agent_trace": ["classify:done"]}


# ── Build the agent graph (fan-out / fan-in) ─────────────────────────────────

def build_scanner_graph():
    g = StateGraph(ScanState)

    g.add_node("clone_repo", clone_repo)
    g.add_node("run_bandit", run_bandit)
    g.add_node("pattern_scan", pattern_scan)
    g.add_node("ai_review", ai_review)
    g.add_node("classify", classify)

    g.set_entry_point("clone_repo")

    def after_clone(state: ScanState):
        if state.get("error"):
            return "classify"
        return ["run_bandit", "pattern_scan", "ai_review"]

    g.add_conditional_edges(
        "clone_repo",
        after_clone,
        ["run_bandit", "pattern_scan", "ai_review", "classify"],
    )

    g.add_edge("run_bandit", "classify")
    g.add_edge("pattern_scan", "classify")
    g.add_edge("ai_review", "classify")
    g.add_edge("classify", END)

    return g.compile()


def run_scan(repo_url: str) -> ScanState:
    graph = build_scanner_graph()
    initial: ScanState = {"repo_url": repo_url}
    result = graph.invoke(initial)
    return result


# ── Haiku-powered chat agent ─────────────────────────────────────────────────

def _get_haiku_llm():
    return ChatAnthropic(
        model="claude-haiku-4-5-20251001",
        temperature=0.3,
        max_tokens=2048,
    )


def chat_with_agent(message: str, scan_context: dict | None = None) -> str:
    """Chat with the Haiku-powered security agent about scan results."""
    llm = _get_haiku_llm()

    context_block = ""
    if scan_context:
        summary = scan_context.get("summary", {})
        vulns = scan_context.get("vulnerabilities", [])
        vuln_summary = "\n".join(
            f"- [{v.get('severity')}] {v.get('title')} in {v.get('file')}:{v.get('line')} ({v.get('source')})"
            for v in vulns[:30]
        )
        context_block = f"""
Current scan results:
- Repository: {scan_context.get('repo_url', 'unknown')}
- Total: {summary.get('total', 0)} | Critical: {summary.get('critical', 0)} | High: {summary.get('high', 0)} | Medium: {summary.get('medium', 0)} | Low: {summary.get('low', 0)}

Vulnerabilities found:
{vuln_summary}
"""

    prompt = f"""You are a security expert assistant integrated into a repository security scanner dashboard.
You help users understand scan results, explain vulnerabilities, suggest fixes, and answer security questions.
Be concise but thorough. Use markdown formatting for code snippets.

{context_block}

User: {message}"""

    try:
        resp = llm.invoke([HumanMessage(content=prompt)])
        return resp.content.strip()
    except Exception as e:
        return f"Agent error: {e}"


def inspect_vulnerability(vuln: dict, scan_context: dict | None = None) -> dict:
    """Deep-dive analysis of a vulnerability with fix suggestions via Haiku."""
    llm = _get_haiku_llm()

    prompt = f"""You are a senior application security engineer. Analyze this vulnerability and provide:

1. **Explanation**: What this vulnerability means and why it's dangerous
2. **Impact**: What could happen if exploited (be specific)
3. **Steps to Fix**: Numbered step-by-step remediation guide
4. **Code Fix**: A concrete code example showing the fix (before/after)
5. **Prevention**: How to prevent this class of vulnerability in the future

Vulnerability:
- Title: {vuln.get('title', 'Unknown')}
- Severity: {vuln.get('severity', 'MEDIUM')}
- File: {vuln.get('file', 'unknown')}
- Line: {vuln.get('line', 0)}
- Source: {vuln.get('source', 'unknown')}
- Description: {vuln.get('description', '')}

Respond with a JSON object:
{{
  "explanation": "...",
  "impact": "...",
  "fix_steps": ["step 1", "step 2", ...],
  "code_before": "vulnerable code example",
  "code_after": "fixed code example",
  "prevention": "..."
}}

Respond ONLY with the JSON object."""

    try:
        resp = llm.invoke([HumanMessage(content=prompt)])
        text = resp.content.strip()
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            return json.loads(match.group())
    except Exception as e:
        return {"explanation": f"Inspection failed: {e}", "impact": "", "fix_steps": [], "code_before": "", "code_after": "", "prevention": ""}

    return {"explanation": "Could not inspect this vulnerability.", "impact": "", "fix_steps": [], "code_before": "", "code_after": "", "prevention": ""}


# ── Jira integration ────────────────────────────────────────────────────────

JIRA_SEVERITY_TO_PRIORITY = {
    "CRITICAL": "Highest",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Lowest",
}


def create_jira_ticket(vuln: dict, project_key: str | None = None, inspect_data: dict | None = None) -> dict:
    """Create a Jira ticket for a vulnerability.

    Requires env vars: JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY (fallback).
    """
    base_url = os.environ.get("JIRA_BASE_URL", "").rstrip("/")
    email = os.environ.get("JIRA_EMAIL", "")
    token = os.environ.get("JIRA_API_TOKEN", "")
    project = project_key or os.environ.get("JIRA_PROJECT_KEY", "")

    if not all([base_url, email, token, project]):
        return {"error": "Jira not configured. Set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY."}

    severity = vuln.get("severity", "MEDIUM")
    title = f"[{severity}] {vuln.get('title', 'Security Issue')}"

    # Build description
    desc_parts = [
        f"*Security vulnerability detected by SecScan Agent*\n",
        f"||Field||Value||",
        f"|Severity|{severity}|",
        f"|File|{{monospace}}{vuln.get('file', 'unknown')}:{vuln.get('line', '?')}{{monospace}}|",
        f"|Source|{vuln.get('source', 'unknown')}|",
        f"|Confidence|{vuln.get('confidence', 'N/A')}|",
        f"|Scan ID|{vuln.get('id', 'N/A')}|",
        f"\n*Description:*\n{vuln.get('description', 'No description available.')}",
    ]

    if inspect_data:
        if inspect_data.get("explanation"):
            desc_parts.append(f"\n*Explanation:*\n{inspect_data['explanation']}")
        if inspect_data.get("impact"):
            desc_parts.append(f"\n*Impact:*\n{inspect_data['impact']}")
        if inspect_data.get("fix_steps"):
            steps = "\n".join(f"# {s}" for s in inspect_data["fix_steps"])
            desc_parts.append(f"\n*Steps to Fix:*\n{steps}")
        if inspect_data.get("code_after"):
            desc_parts.append(f"\n*Suggested Fix:*\n{{code}}\n{inspect_data['code_after']}\n{{code}}")
        if inspect_data.get("prevention"):
            desc_parts.append(f"\n*Prevention:*\n{inspect_data['prevention']}")

    payload = {
        "fields": {
            "project": {"key": project},
            "summary": title[:255],
            "description": "\n".join(desc_parts),
            "issuetype": {"name": "Bug"},
            "priority": {"name": JIRA_SEVERITY_TO_PRIORITY.get(severity, "Medium")},
            "labels": ["security", "secscan", severity.lower()],
        }
    }

    try:
        resp = http_requests.post(
            f"{base_url}/rest/api/2/issue",
            json=payload,
            auth=(email, token),
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        if resp.status_code in (200, 201):
            data = resp.json()
            return {
                "success": True,
                "key": data.get("key", ""),
                "url": f"{base_url}/browse/{data.get('key', '')}",
                "id": data.get("id", ""),
            }
        else:
            return {"error": f"Jira API error ({resp.status_code}): {resp.text[:300]}"}
    except Exception as e:
        return {"error": f"Failed to create Jira ticket: {e}"}

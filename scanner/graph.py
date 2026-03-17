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


def _get_jira_auth() -> tuple[str, str, str, str]:
    """Return (base_url, email, token, project) from env vars."""
    return (
        os.environ.get("JIRA_BASE_URL", "").rstrip("/"),
        os.environ.get("JIRA_EMAIL", ""),
        os.environ.get("JIRA_API_TOKEN", ""),
        os.environ.get("JIRA_PROJECT_KEY", ""),
    )


def _get_active_sprint_id() -> int | None:
    """Find the active sprint ID for the project's board."""
    base_url, email, token, project = _get_jira_auth()
    if not all([base_url, email, token, project]):
        return None
    try:
        # Get boards for the project
        resp = http_requests.get(
            f"{base_url}/rest/agile/1.0/board",
            params={"projectKeyOrId": project},
            auth=(email, token),
            headers={"Accept": "application/json"},
            timeout=10,
        )
        if resp.status_code != 200:
            return None
        boards = resp.json().get("values", [])
        if not boards:
            return None
        board_id = boards[0]["id"]

        # Get active sprint
        resp2 = http_requests.get(
            f"{base_url}/rest/agile/1.0/board/{board_id}/sprint",
            params={"state": "active"},
            auth=(email, token),
            headers={"Accept": "application/json"},
            timeout=10,
        )
        if resp2.status_code != 200:
            return None
        sprints = resp2.json().get("values", [])
        return sprints[0]["id"] if sprints else None
    except Exception:
        return None


def _generate_ticket_analysis(vuln: dict) -> dict | None:
    """Use AI to generate detailed analysis for a Jira ticket."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return None

    llm = ChatAnthropic(model="claude-haiku-4-5-20251001", temperature=0, max_tokens=4096)

    prompt = f"""You are a senior application security engineer writing a detailed Jira ticket for a development team.
Analyze this vulnerability and provide comprehensive, actionable instructions.

Vulnerability:
- Title: {vuln.get('title', 'Unknown')}
- Severity: {vuln.get('severity', 'MEDIUM')}
- File: {vuln.get('file', 'unknown')}
- Line: {vuln.get('line', 0)}
- Source Scanner: {vuln.get('source', 'unknown')}
- Description: {vuln.get('description', '')}

Respond with a JSON object:
{{
  "explanation": "2-3 sentences explaining what this vulnerability is and why it exists in the code",
  "impact": "2-3 sentences on what an attacker could achieve if they exploit this. Be specific about the attack scenario.",
  "fix_steps": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
  "code_before": "example of the vulnerable code pattern",
  "code_after": "example of the fixed code pattern",
  "prevention": "How to prevent this class of vulnerability going forward (e.g., linting rules, code review checklist items, libraries to use)",
  "references": "Relevant OWASP links, CWE IDs, or security best practice references"
}}

Respond ONLY with the JSON object."""

    try:
        resp = llm.invoke([HumanMessage(content=prompt)])
        text = resp.content.strip()
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            return json.loads(match.group())
    except Exception:
        pass
    return None


def create_jira_ticket(vuln: dict, project_key: str | None = None, inspect_data: dict | None = None) -> dict:
    """Create a Jira ticket for a vulnerability.

    Requires env vars: JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY (fallback).
    """
    base_url, email, token, default_project = _get_jira_auth()
    project = project_key or default_project

    if not all([base_url, email, token, project]):
        return {"error": "Jira not configured. Set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY."}

    severity = vuln.get("severity", "MEDIUM")
    title = f"[{severity}] {vuln.get('title', 'Security Issue')}"

    # Generate AI-powered detailed analysis for the ticket
    ai_analysis = _generate_ticket_analysis(vuln)

    # Build description
    desc_parts = [
        f"h2. Security Vulnerability Detected by SecScan Agent\n",
        f"||Field||Value||",
        f"|Severity|*{severity}*|",
        f"|File|{{monospace}}{vuln.get('file', 'unknown')}:{vuln.get('line', '?')}{{monospace}}|",
        f"|Scanner Source|{vuln.get('source', 'unknown')}|",
        f"|Confidence|{vuln.get('confidence', 'N/A')}|",
        f"|Scan ID|{vuln.get('id', 'N/A')}|",
        f"\nh3. What Was Found",
        f"{vuln.get('description', 'No description available.')}",
    ]

    # Add AI-generated analysis
    if ai_analysis:
        desc_parts.append(f"\nh3. Why This Is Dangerous")
        desc_parts.append(ai_analysis.get("explanation", ""))
        desc_parts.append(f"\nh3. Potential Impact")
        desc_parts.append(ai_analysis.get("impact", ""))
        if ai_analysis.get("fix_steps"):
            desc_parts.append(f"\nh3. Step-by-Step Fix Instructions")
            for i, step in enumerate(ai_analysis["fix_steps"], 1):
                desc_parts.append(f"# {step}")
        if ai_analysis.get("code_before"):
            desc_parts.append(f"\nh3. Vulnerable Code (Before)")
            desc_parts.append(f"{{code}}\n{ai_analysis['code_before']}\n{{code}}")
        if ai_analysis.get("code_after"):
            desc_parts.append(f"\nh3. Fixed Code (After)")
            desc_parts.append(f"{{code}}\n{ai_analysis['code_after']}\n{{code}}")
        if ai_analysis.get("prevention"):
            desc_parts.append(f"\nh3. How to Prevent This in Future")
            desc_parts.append(ai_analysis["prevention"])
        if ai_analysis.get("references"):
            desc_parts.append(f"\nh3. References")
            desc_parts.append(ai_analysis["references"])
    elif inspect_data:
        if inspect_data.get("explanation"):
            desc_parts.append(f"\nh3. Why This Is Dangerous")
            desc_parts.append(inspect_data['explanation'])
        if inspect_data.get("impact"):
            desc_parts.append(f"\nh3. Potential Impact")
            desc_parts.append(inspect_data['impact'])
        if inspect_data.get("fix_steps"):
            desc_parts.append(f"\nh3. Step-by-Step Fix Instructions")
            for i, step in enumerate(inspect_data["fix_steps"], 1):
                desc_parts.append(f"# {step}")
        if inspect_data.get("code_before"):
            desc_parts.append(f"\nh3. Vulnerable Code (Before)")
            desc_parts.append(f"{{code}}\n{inspect_data['code_before']}\n{{code}}")
        if inspect_data.get("code_after"):
            desc_parts.append(f"\nh3. Fixed Code (After)")
            desc_parts.append(f"{{code}}\n{inspect_data['code_after']}\n{{code}}")
        if inspect_data.get("prevention"):
            desc_parts.append(f"\nh3. How to Prevent This in Future")
            desc_parts.append(inspect_data['prevention'])

    desc_parts.append(f"\n----")
    desc_parts.append(f"_Auto-generated by SecScan Agent_")

    fields = {
        "project": {"key": project},
        "summary": title[:255],
        "description": "\n".join(desc_parts),
        "issuetype": {"name": "Bug"},
        "priority": {"name": JIRA_SEVERITY_TO_PRIORITY.get(severity, "Medium")},
        "labels": ["security", "secscan", severity.lower()],
    }

    # Try to assign to active sprint so ticket lands in To Do, not Backlog
    sprint_id = _get_active_sprint_id()
    if sprint_id:
        fields["customfield_10020"] = sprint_id  # Sprint field

    payload = {"fields": fields}

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


def create_jira_tickets_bulk(vulns: list[dict], severity_filter: str = "CRITICAL") -> dict:
    """Create Jira tickets for all vulnerabilities matching the severity filter.

    Returns a summary with created tickets and any errors.
    """
    filtered = [v for v in vulns if v.get("severity") == severity_filter]
    if not filtered:
        return {"created": [], "errors": [], "total": 0, "message": f"No {severity_filter} issues found."}

    created = []
    errors = []
    for vuln in filtered:
        result = create_jira_ticket(vuln)
        if result.get("error"):
            errors.append({"vuln_id": vuln.get("id", "?"), "title": vuln.get("title", "?"), "error": result["error"]})
        else:
            created.append({"vuln_id": vuln.get("id", "?"), "title": vuln.get("title", "?"), "key": result["key"], "url": result["url"]})

    return {
        "created": created,
        "errors": errors,
        "total": len(filtered),
        "success_count": len(created),
        "error_count": len(errors),
    }


# ── Fetch Jira security tickets ───────────────────────────────────────────

def fetch_jira_security_tickets() -> list[dict]:
    """Fetch open security-labelled tickets from Jira."""
    base_url, email, token, project = _get_jira_auth()
    if not all([base_url, email, token, project]):
        return []

    jql = f"project={project} AND labels=security AND status != Done ORDER BY priority DESC"

    # Try v3 search first (new Jira Cloud), fall back to v2
    for api_path in ["/rest/api/3/search/jql", "/rest/api/2/search"]:
        try:
            if "jql" in api_path:
                # v3 uses POST with JSON body
                resp = http_requests.post(
                    f"{base_url}{api_path}",
                    json={"jql": jql, "maxResults": 50, "fields": ["summary", "description", "status", "priority", "labels"]},
                    auth=(email, token),
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                    timeout=15,
                )
            else:
                resp = http_requests.get(
                    f"{base_url}{api_path}",
                    params={"jql": jql, "maxResults": 50, "fields": "summary,description,status,priority,labels"},
                    auth=(email, token),
                    headers={"Accept": "application/json"},
                    timeout=15,
                )
            if resp.status_code == 200:
                issues = resp.json().get("issues", [])
                return [
                    {
                        "key": iss["key"],
                        "summary": iss["fields"].get("summary", ""),
                        "description": iss["fields"].get("description", ""),
                        "status": iss["fields"].get("status", {}).get("name", ""),
                        "priority": iss["fields"].get("priority", {}).get("name", ""),
                        "labels": iss["fields"].get("labels", []),
                    }
                    for iss in issues
                ]
        except Exception:
            continue
    return []


# ── Auto-fix agent ────────────────────────────────────────────────────────

def _generate_fix_for_vuln(vuln_title: str, vuln_description: str, file_path: str, file_content: str) -> dict | None:
    """Use AI to generate a code fix for a vulnerability."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return None

    llm = ChatAnthropic(model="claude-haiku-4-5-20251001", temperature=0, max_tokens=4096)

    prompt = f"""You are a senior security engineer. Fix the security vulnerability described below in the given file.

Vulnerability: {vuln_title}
Description: {vuln_description}
File: {file_path}

Current file content:
```
{file_content[:6000]}
```

Respond with a JSON object:
{{
  "fixed_content": "the complete fixed file content",
  "changes_summary": "brief description of what was changed and why"
}}

Respond ONLY with the JSON object. The fixed_content must be the COMPLETE file, not a diff."""

    try:
        resp = llm.invoke([HumanMessage(content=prompt)])
        text = resp.content.strip()
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            return json.loads(match.group())
    except Exception:
        pass
    return None


def autofix_from_scan(repo_url: str, vulnerabilities: list[dict]) -> dict:
    """Clone repo, fix vulnerabilities, create branch, commit, push, and create PR.

    Returns a summary of what was fixed and the PR URL.
    """
    if not vulnerabilities:
        return {"error": "No vulnerabilities to fix.", "fixes": []}

    # Only fix CRITICAL and HIGH
    fixable = [v for v in vulnerabilities if v.get("severity") in ("CRITICAL", "HIGH")]
    if not fixable:
        return {"error": "No CRITICAL or HIGH vulnerabilities to auto-fix.", "fixes": []}

    # Clone repo
    tmp = tempfile.mkdtemp(prefix="autofix_")
    try:
        subprocess.run(
            ["git", "clone", repo_url, tmp],
            check=True, capture_output=True, text=True, timeout=120,
        )
    except subprocess.CalledProcessError as e:
        return {"error": f"Clone failed: {e.stderr}", "fixes": []}

    branch_name = "autofix/security-vulnerabilities"
    try:
        subprocess.run(["git", "checkout", "-b", branch_name], cwd=tmp, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError:
        pass

    fixes = _apply_fixes_to_repo(tmp, fixable)

    return _commit_push_and_pr(tmp, fixes, branch_name, repo_url)


def autofix_from_jira(repo_url: str) -> dict:
    """Fetch all open security tickets from Jira, clone repo, fix all issues, and raise a PR.

    This is the Jira-driven auto-fix agent:
    1. Fetches all open security tickets from the configured Jira project
    2. Parses vulnerability details (file, line, title, description) from each ticket
    3. Clones the target repository
    4. Creates a new branch 'security-fixes'
    5. Uses AI to generate and apply fixes for each vulnerability
    6. Commits all changes, pushes the branch, and opens a PR
    7. Transitions fixed Jira tickets to 'Done'
    """
    if not repo_url:
        return {"error": "repo_url is required.", "fixes": []}

    # Step 1: Fetch open security tickets from Jira
    tickets = fetch_jira_security_tickets()
    if not tickets:
        return {"error": "No open security tickets found in Jira.", "fixes": [], "tickets_found": 0}

    # Step 2: Parse vulnerability info from ticket summaries/descriptions
    vulns_from_jira = _parse_jira_tickets_to_vulns(tickets)
    if not vulns_from_jira:
        return {"error": "Could not parse vulnerability details from Jira tickets.", "fixes": [], "tickets_found": len(tickets)}

    # Step 3: Clone repo
    tmp = tempfile.mkdtemp(prefix="jirafix_")
    try:
        subprocess.run(
            ["git", "clone", repo_url, tmp],
            check=True, capture_output=True, text=True, timeout=120,
        )
    except subprocess.CalledProcessError as e:
        return {"error": f"Clone failed: {e.stderr}", "fixes": []}

    # Step 4: Create branch
    branch_name = "security-fixes"
    try:
        subprocess.run(["git", "checkout", "-b", branch_name], cwd=tmp, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError:
        # Branch might exist, try switching
        try:
            subprocess.run(["git", "checkout", branch_name], cwd=tmp, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError:
            pass

    # Step 5: Apply AI fixes
    fixes = _apply_fixes_to_repo(tmp, vulns_from_jira)

    # Step 6: Commit, push, and create PR
    result = _commit_push_and_pr(tmp, fixes, branch_name, repo_url)

    # Step 7: Transition fixed tickets to Done in Jira
    applied = [f for f in fixes if f["status"] == "fixed"]
    transitioned = []
    for fix in applied:
        jira_key = fix.get("jira_key", "")
        if jira_key:
            success = _transition_jira_ticket_done(jira_key)
            transitioned.append({"key": jira_key, "transitioned": success})

    result["tickets_found"] = len(tickets)
    result["tickets_parsed"] = len(vulns_from_jira)
    result["tickets_transitioned"] = transitioned
    return result


def _parse_jira_tickets_to_vulns(tickets: list[dict]) -> list[dict]:
    """Parse Jira ticket summaries and descriptions to extract vulnerability details."""
    vulns = []
    for ticket in tickets:
        summary = ticket.get("summary", "")
        description = ticket.get("description", "")
        jira_key = ticket.get("key", "")

        # If description is ADF (dict), extract text
        if isinstance(description, dict):
            description = _extract_text_from_adf(description)

        # Extract severity from summary like "[CRITICAL] Title"
        severity = "HIGH"
        sev_match = re.search(r'\[(CRITICAL|HIGH|MEDIUM|LOW)\]', summary)
        if sev_match:
            severity = sev_match.group(1)

        # Extract file path and line from description
        file_path = ""
        line_num = 0
        file_match = re.search(r'(?:File|file)[:\s|]*[{]?(?:monospace)?[}]?\s*([^\s|{}\n]+\.\w+):?(\d+)?', description)
        if file_match:
            file_path = file_match.group(1)
            if file_match.group(2):
                line_num = int(file_match.group(2))

        # Clean title from summary
        title = re.sub(r'\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*', '', summary).strip()

        vulns.append({
            "id": jira_key,
            "jira_key": jira_key,
            "file": file_path,
            "line": line_num,
            "severity": severity,
            "title": title,
            "description": description[:2000],
            "source": "jira",
        })

    return vulns


def _extract_text_from_adf(adf: dict) -> str:
    """Recursively extract plain text from Atlassian Document Format."""
    if isinstance(adf, str):
        return adf
    text_parts = []
    if isinstance(adf, dict):
        if adf.get("type") == "text":
            text_parts.append(adf.get("text", ""))
        for child in adf.get("content", []):
            text_parts.append(_extract_text_from_adf(child))
    elif isinstance(adf, list):
        for item in adf:
            text_parts.append(_extract_text_from_adf(item))
    return " ".join(text_parts)


def _apply_fixes_to_repo(repo_path: str, vulns: list[dict]) -> list[dict]:
    """Apply AI-generated fixes for each vulnerability in the cloned repo."""
    fixes = []
    for vuln in vulns:
        file_rel = vuln.get("file", "")
        if not file_rel:
            fixes.append({
                "vuln_id": vuln.get("id", "?"), "jira_key": vuln.get("jira_key", ""),
                "title": vuln.get("title", ""), "status": "skipped", "reason": "no file path found",
            })
            continue
        file_abs = os.path.join(repo_path, file_rel)
        if not os.path.isfile(file_abs):
            fixes.append({
                "vuln_id": vuln.get("id", "?"), "jira_key": vuln.get("jira_key", ""),
                "title": vuln.get("title", ""), "status": "skipped", "reason": "file not found",
            })
            continue

        try:
            with open(file_abs, "r", errors="ignore") as f:
                original = f.read()
        except Exception:
            fixes.append({
                "vuln_id": vuln.get("id", "?"), "jira_key": vuln.get("jira_key", ""),
                "title": vuln.get("title", ""), "status": "skipped", "reason": "could not read file",
            })
            continue

        fix_result = _generate_fix_for_vuln(
            vuln.get("title", ""), vuln.get("description", ""), file_rel, original
        )
        if not fix_result or not fix_result.get("fixed_content"):
            fixes.append({
                "vuln_id": vuln.get("id", "?"), "jira_key": vuln.get("jira_key", ""),
                "title": vuln.get("title", ""), "status": "failed", "reason": "AI could not generate fix",
            })
            continue

        fixed_content = fix_result["fixed_content"]
        if fixed_content.strip() == original.strip():
            fixes.append({
                "vuln_id": vuln.get("id", "?"), "jira_key": vuln.get("jira_key", ""),
                "title": vuln.get("title", ""), "status": "skipped", "reason": "no changes needed",
            })
            continue

        with open(file_abs, "w") as f:
            f.write(fixed_content)

        fixes.append({
            "vuln_id": vuln.get("id", "?"),
            "jira_key": vuln.get("jira_key", ""),
            "title": vuln.get("title", ""),
            "file": file_rel,
            "status": "fixed",
            "summary": fix_result.get("changes_summary", ""),
        })

    return fixes


def _commit_push_and_pr(repo_path: str, fixes: list[dict], branch_name: str, repo_url: str) -> dict:
    """Commit fixes, push branch, and create PR. Returns result dict."""
    applied = [f for f in fixes if f["status"] == "fixed"]
    if not applied:
        shutil.rmtree(repo_path, ignore_errors=True)
        return {"fixes": fixes, "pr_url": None, "fixed_count": 0, "message": "No fixes could be applied."}

    try:
        subprocess.run(["git", "add", "-A"], cwd=repo_path, check=True, capture_output=True, text=True)

        commit_msg = f"fix: resolve {len(applied)} security vulnerabilities\n\n"
        for f in applied:
            jira_ref = f" ({f['jira_key']})" if f.get("jira_key") else ""
            commit_msg += f"- [{f['vuln_id']}] {f['title']} in {f.get('file', '?')}{jira_ref}\n"
        commit_msg += "\nGenerated by SecScan Agent"

        subprocess.run(
            ["git", "commit", "-m", commit_msg],
            cwd=repo_path, check=True, capture_output=True, text=True,
            env={**os.environ, "GIT_AUTHOR_NAME": "SecScan Agent", "GIT_AUTHOR_EMAIL": "secscan@agent.local",
                 "GIT_COMMITTER_NAME": "SecScan Agent", "GIT_COMMITTER_EMAIL": "secscan@agent.local"},
        )

        subprocess.run(
            ["git", "push", "-u", "origin", branch_name],
            cwd=repo_path, check=True, capture_output=True, text=True, timeout=60,
        )
    except subprocess.CalledProcessError as e:
        shutil.rmtree(repo_path, ignore_errors=True)
        return {"fixes": fixes, "pr_url": None, "error": f"Git push failed: {e.stderr[:300]}"}

    # Create PR
    pr_url = None
    pr_body = "## Security Fixes\n\n"
    pr_body += f"Resolved **{len(applied)}** security vulnerabilities found by SecScan Agent.\n\n"
    pr_body += "### Changes\n\n"
    for f in applied:
        jira_ref = f" ({f['jira_key']})" if f.get("jira_key") else ""
        pr_body += f"- **[{f['vuln_id']}]** {f['title']} in `{f.get('file', '?')}`{jira_ref}\n"
        if f.get("summary"):
            pr_body += f"  - {f['summary']}\n"
    pr_body += "\n---\n*Generated by SecScan Agent*"

    try:
        result = subprocess.run(
            ["gh", "pr", "create", "--title", f"fix: resolve {len(applied)} security vulnerabilities",
             "--body", pr_body, "--head", branch_name],
            cwd=repo_path, capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            pr_url = result.stdout.strip()
    except Exception:
        pass

    shutil.rmtree(repo_path, ignore_errors=True)

    return {
        "fixes": fixes,
        "pr_url": pr_url,
        "fixed_count": len(applied),
        "total_attempted": len([f for f in fixes]),
        "message": f"Fixed {len(applied)}/{len(fixes)} vulnerabilities." + (f" PR: {pr_url}" if pr_url else " Push succeeded but PR creation failed (gh CLI may not be configured)."),
    }


def _transition_jira_ticket_done(issue_key: str) -> bool:
    """Transition a Jira ticket to 'Done' status."""
    base_url, email, token, _ = _get_jira_auth()
    if not all([base_url, email, token]):
        return False

    try:
        # Get available transitions
        resp = http_requests.get(
            f"{base_url}/rest/api/2/issue/{issue_key}/transitions",
            auth=(email, token),
            headers={"Accept": "application/json"},
            timeout=10,
        )
        if resp.status_code != 200:
            return False

        transitions = resp.json().get("transitions", [])
        done_id = None
        for t in transitions:
            if t["name"].lower() in ("done", "resolved", "closed", "complete"):
                done_id = t["id"]
                break

        if not done_id:
            return False

        # Execute transition
        resp2 = http_requests.post(
            f"{base_url}/rest/api/2/issue/{issue_key}/transitions",
            json={"transition": {"id": done_id}},
            auth=(email, token),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        return resp2.status_code == 204
    except Exception:
        return False

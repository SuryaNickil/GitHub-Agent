"""Flask dashboard for the security scanner agent."""

from __future__ import annotations

from datetime import datetime, timezone

from flask import Flask, jsonify, render_template_string, request

from .graph import autofix_from_scan, chat_with_agent, create_jira_ticket, create_jira_tickets_bulk, fetch_jira_security_tickets, inspect_vulnerability, run_scan

app = Flask(__name__)

# Store latest scan for chat context
_latest_scan: dict = {}

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecScan Agent</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
/* ── Theme variables ── */
[data-theme="dark"] {
  --bg: #000000; --bg2: #0a0a0a; --surface: #111111; --surface2: #1a1a1a; --surface3: #252525; --border: #2a2a2a;
  --text: #ffffff; --text2: #e0e0e0; --muted: #666666; --dim: #444444;
  --glass: rgba(17,17,17,0.7); --glass-border: rgba(255,255,255,0.06);
  --critical: #ff3b3b; --critical-bg: rgba(255,59,59,0.08); --critical-border: rgba(255,59,59,0.2);
  --high: #ff8c00; --high-bg: rgba(255,140,0,0.08); --high-border: rgba(255,140,0,0.2);
  --medium: #ffd000; --medium-bg: rgba(255,208,0,0.08); --medium-border: rgba(255,208,0,0.2);
  --low: #00d4ff; --low-bg: rgba(0,212,255,0.08); --low-border: rgba(0,212,255,0.2);
  --accent: #7c5cfc; --accent2: #5b3cf5; --accent-glow: rgba(124,92,252,0.15);
  --green: #00e676; --green-bg: rgba(0,230,118,0.08);
  --shadow: 0 8px 32px rgba(0,0,0,0.6);
  --card-shadow: 0 4px 24px rgba(0,0,0,0.4);
}
[data-theme="light"] {
  --bg: #f5f5f7; --bg2: #eeeef0; --surface: #ffffff; --surface2: #f0f0f2; --surface3: #e5e5ea; --border: #d1d1d6;
  --text: #1a1a1a; --text2: #333333; --muted: #8e8e93; --dim: #aeaeb2;
  --glass: rgba(255,255,255,0.75); --glass-border: rgba(0,0,0,0.06);
  --critical: #e0301e; --critical-bg: rgba(224,48,30,0.06); --critical-border: rgba(224,48,30,0.15);
  --high: #e67700; --high-bg: rgba(230,119,0,0.06); --high-border: rgba(230,119,0,0.15);
  --medium: #c49a00; --medium-bg: rgba(196,154,0,0.06); --medium-border: rgba(196,154,0,0.15);
  --low: #0091b3; --low-bg: rgba(0,145,179,0.06); --low-border: rgba(0,145,179,0.15);
  --accent: #6842d0; --accent2: #5530b8; --accent-glow: rgba(104,66,208,0.08);
  --green: #00a854; --green-bg: rgba(0,168,84,0.06);
  --shadow: 0 8px 32px rgba(0,0,0,0.08);
  --card-shadow: 0 2px 12px rgba(0,0,0,0.06);
}

* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Inter', -apple-system, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; transition: background 0.4s, color 0.4s; overflow-x: hidden; }

/* ── Header ── */
.header {
  position: sticky; top: 0; z-index: 100; padding: 1rem 2rem;
  background: var(--glass); backdrop-filter: blur(20px) saturate(180%); -webkit-backdrop-filter: blur(20px) saturate(180%);
  border-bottom: 1px solid var(--glass-border);
}
.header-inner { max-width: 1400px; margin: 0 auto; display: flex; align-items: center; gap: 1rem; }
.logo {
  width: 38px; height: 38px; border-radius: 10px; display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, var(--accent), #a855f7); font-size: 1.1rem; flex-shrink: 0;
  box-shadow: 0 0 20px var(--accent-glow);
}
.header h1 { font-size: 1.15rem; font-weight: 800; letter-spacing: -0.03em; flex: 1; }
.header-actions { display: flex; align-items: center; gap: 0.75rem; }

/* Theme toggle */
.theme-toggle {
  width: 52px; height: 28px; border-radius: 14px; background: var(--surface3); border: 1px solid var(--border);
  cursor: pointer; position: relative; transition: all 0.3s; flex-shrink: 0;
}
.theme-toggle::after {
  content: ''; position: absolute; top: 3px; left: 3px; width: 20px; height: 20px; border-radius: 50%;
  background: var(--text); transition: transform 0.3s ease;
}
[data-theme="light"] .theme-toggle::after { transform: translateX(24px); }
.theme-label { font-size: 0.7rem; color: var(--muted); font-weight: 500; }

/* ── Layout ── */
.main-layout { max-width: 1200px; margin: 0 auto; }
.content-area { padding: 2rem; }

/* ── Scan form ── */
.scan-section { margin-bottom: 2rem; }
.scan-form { display: flex; gap: 0.5rem; }
.scan-form input {
  flex: 1; padding: 0.8rem 1rem; background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; color: var(--text); font-family: 'JetBrains Mono', monospace; font-size: 0.82rem;
  outline: none; transition: all 0.3s;
}
.scan-form input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
.scan-form input::placeholder { color: var(--dim); }
.scan-btn {
  padding: 0.8rem 1.8rem; background: var(--accent); border: none; border-radius: 12px;
  color: #fff; font-weight: 700; font-size: 0.82rem; cursor: pointer; transition: all 0.3s;
  font-family: 'Inter', sans-serif; white-space: nowrap;
}
.scan-btn:hover { background: var(--accent2); transform: translateY(-1px); box-shadow: 0 4px 20px var(--accent-glow); }
.scan-btn:disabled { opacity: 0.4; cursor: not-allowed; transform: none; box-shadow: none; }

/* ── Pipeline ── */
.pipeline { display: none; margin-bottom: 1.5rem; padding: 1.2rem; background: var(--surface); border-radius: 14px; border: 1px solid var(--border); }
.pipeline.visible { display: block; }
.pipeline-label { font-size: 0.6rem; text-transform: uppercase; letter-spacing: 0.12em; color: var(--dim); margin-bottom: 0.8rem; font-weight: 600; }
.pipeline-row { display: flex; align-items: center; gap: 0.4rem; justify-content: center; flex-wrap: wrap; }
.pnode {
  padding: 0.5rem 0.9rem; border-radius: 8px; background: var(--surface2); border: 1px solid var(--border);
  font-size: 0.68rem; font-weight: 600; color: var(--muted); transition: all 0.4s; white-space: nowrap;
}
.pnode.running { color: var(--accent); border-color: var(--accent); box-shadow: 0 0 12px var(--accent-glow); animation: npulse 1.5s ease-in-out infinite; }
.pnode.done { color: var(--green); border-color: rgba(0,230,118,0.3); }
.pnode.error { color: var(--critical); border-color: var(--critical-border); }
.parrow { color: var(--dim); font-size: 0.8rem; }
.pbracket { color: var(--dim); font-size: 1.4rem; font-weight: 200; }
@keyframes npulse { 0%,100% { box-shadow: 0 0 8px var(--accent-glow); } 50% { box-shadow: 0 0 20px var(--accent-glow); } }

/* ── Status ── */
.status-bar { display: none; padding: 0.7rem 1rem; border-radius: 10px; margin-bottom: 1.5rem; font-size: 0.78rem; align-items: center; gap: 0.6rem; background: var(--surface); border: 1px solid var(--border); }
.status-bar.visible { display: flex; }
.status-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
.status-bar.scanning .status-dot { background: var(--accent); animation: dpulse 1s infinite; }
.status-bar.done .status-dot { background: var(--green); }
.status-bar.done { color: var(--green); border-color: rgba(0,230,118,0.2); }
.status-bar.error .status-dot { background: var(--critical); }
.status-bar.error { color: var(--critical); border-color: var(--critical-border); }
@keyframes dpulse { 0%,100% { opacity:1; } 50% { opacity:0.3; } }

/* ── Severity cards (3D) ── */
.severity-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.75rem; margin-bottom: 2rem; perspective: 800px; }
.sev-card {
  background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 1.5rem 1rem;
  text-align: center; cursor: pointer; transition: all 0.35s ease; position: relative; overflow: hidden;
  transform-style: preserve-3d;
}
.sev-card::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; border-radius: 16px 16px 0 0;
  transition: height 0.3s;
}
.sev-card:hover { transform: translateY(-4px) rotateX(2deg); box-shadow: var(--card-shadow); }
.sev-card.active { border-color: var(--accent); box-shadow: 0 0 20px var(--accent-glow); transform: translateY(-4px) scale(1.02); }
.sev-card .num { font-size: 2.2rem; font-weight: 900; letter-spacing: -0.04em; line-height: 1; }
.sev-card .lbl { font-size: 0.6rem; text-transform: uppercase; letter-spacing: 0.12em; color: var(--muted); margin-top: 0.5rem; font-weight: 600; }
.sev-card.s-total::before { background: linear-gradient(90deg, var(--accent), #a855f7); } .sev-card.s-total .num { color: var(--accent); }
.sev-card.s-critical::before { background: var(--critical); } .sev-card.s-critical .num { color: var(--critical); }
.sev-card.s-high::before { background: var(--high); } .sev-card.s-high .num { color: var(--high); }
.sev-card.s-medium::before { background: var(--medium); } .sev-card.s-medium .num { color: var(--medium); }
.sev-card.s-low::before { background: var(--low); } .sev-card.s-low .num { color: var(--low); }

/* ── Vuln list (hidden by default) ── */
.vuln-section { display: none; margin-bottom: 2rem; }
.vuln-section.visible { display: block; animation: slideDown 0.3s ease; }
.vuln-section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem; }
.vuln-section-title { font-size: 0.85rem; font-weight: 700; }
.vuln-close { background: none; border: 1px solid var(--border); border-radius: 8px; padding: 0.3rem 0.7rem; color: var(--muted); cursor: pointer; font-size: 0.72rem; font-family: 'Inter', sans-serif; transition: all 0.2s; }
.vuln-close:hover { border-color: var(--text); color: var(--text); }
@keyframes slideDown { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }

.vuln-list { display: flex; flex-direction: column; gap: 0.4rem; max-height: 400px; overflow-y: auto; padding-right: 0.3rem; }
.vuln-list::-webkit-scrollbar { width: 5px; }
.vuln-list::-webkit-scrollbar-track { background: transparent; }
.vuln-list::-webkit-scrollbar-thumb { background: var(--surface3); border-radius: 3px; }
.vuln-list::-webkit-scrollbar-thumb:hover { background: var(--dim); }
.vuln-item {
  display: flex; align-items: center; gap: 0.75rem; padding: 0.85rem 1rem; background: var(--surface);
  border: 1px solid var(--border); border-radius: 12px; cursor: pointer; transition: all 0.25s;
}
.vuln-item:hover { border-color: var(--accent); background: var(--surface2); transform: translateX(4px); }
.sev-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.sev-dot.CRITICAL { background: var(--critical); box-shadow: 0 0 8px var(--critical-bg); }
.sev-dot.HIGH { background: var(--high); box-shadow: 0 0 8px var(--high-bg); }
.sev-dot.MEDIUM { background: var(--medium); }
.sev-dot.LOW { background: var(--low); }
.vuln-item-title { flex: 1; font-size: 0.8rem; font-weight: 500; }
.vuln-item-file { font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: var(--muted); max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.vuln-item-src { font-size: 0.6rem; padding: 0.15rem 0.45rem; background: var(--surface3); border-radius: 4px; color: var(--muted); font-weight: 600; text-transform: uppercase; }

/* ── Inspect panel (overlay) ── */
.inspect-overlay { display: none; position: fixed; inset: 0; z-index: 200; background: rgba(0,0,0,0.6); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); }
.inspect-overlay.visible { display: flex; align-items: center; justify-content: center; animation: fadeIn 0.25s ease; }
.inspect-panel {
  width: 700px; max-width: 92vw; max-height: 85vh; overflow-y: auto; background: var(--surface);
  border: 1px solid var(--border); border-radius: 20px; padding: 2rem; box-shadow: var(--shadow);
  animation: scaleIn 0.3s ease;
}
@keyframes scaleIn { from { transform: scale(0.95); opacity: 0; } to { transform: scale(1); opacity: 1; } }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
.inspect-header { display: flex; align-items: flex-start; gap: 1rem; margin-bottom: 1.5rem; }
.inspect-sev { padding: 0.3rem 0.7rem; border-radius: 6px; font-size: 0.65rem; font-weight: 700; text-transform: uppercase; }
.inspect-sev.CRITICAL { background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical-border); }
.inspect-sev.HIGH { background: var(--high-bg); color: var(--high); border: 1px solid var(--high-border); }
.inspect-sev.MEDIUM { background: var(--medium-bg); color: var(--medium); border: 1px solid var(--medium-border); }
.inspect-sev.LOW { background: var(--low-bg); color: var(--low); border: 1px solid var(--low-border); }
.inspect-title { font-size: 1.1rem; font-weight: 700; flex: 1; }
.inspect-close { background: none; border: 1px solid var(--border); border-radius: 8px; width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; cursor: pointer; color: var(--muted); font-size: 1rem; transition: all 0.2s; }
.inspect-close:hover { border-color: var(--text); color: var(--text); }
.inspect-meta { display: flex; gap: 1rem; margin-bottom: 1.5rem; font-size: 0.75rem; color: var(--muted); flex-wrap: wrap; }
.inspect-meta span { padding: 0.3rem 0.6rem; background: var(--surface2); border-radius: 6px; }
.inspect-meta .file-link { font-family: 'JetBrains Mono', monospace; color: var(--accent); }
.inspect-body { font-size: 0.82rem; line-height: 1.7; color: var(--text2); }
.inspect-body h3 { font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; margin: 1.5rem 0 0.5rem; color: var(--text); }
.inspect-body h3:first-child { margin-top: 0; }
.inspect-body p { margin-bottom: 0.5rem; }
.inspect-body pre { background: var(--surface2); border: 1px solid var(--border); border-radius: 10px; padding: 1rem; overflow-x: auto; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; margin: 0.5rem 0; line-height: 1.6; }
.inspect-body ol, .inspect-body ul { padding-left: 1.2rem; margin-bottom: 0.5rem; }
.inspect-body li { margin-bottom: 0.3rem; }
.inspect-loading { text-align: center; padding: 3rem; color: var(--muted); }
.inspect-loading .spinner { display: inline-block; width: 28px; height: 28px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; margin-bottom: 0.8rem; }
@keyframes spin { to { transform: rotate(360deg); } }

/* ── Chat floating popup ── */
.chat-fab {
  position: fixed; right: 1.5rem; bottom: 1.5rem; z-index: 300; width: 54px; height: 54px;
  border-radius: 50%; background: linear-gradient(135deg, var(--accent), #7c3aed); border: none; color: #fff; font-size: 1.3rem;
  cursor: pointer; box-shadow: 0 4px 24px var(--accent-glow); transition: all 0.3s;
  display: flex; align-items: center; justify-content: center;
}
.chat-fab:hover { transform: scale(1.1); box-shadow: 0 6px 30px var(--accent-glow); }
.chat-popup {
  display: none; position: fixed; right: 1.5rem; bottom: 5.5rem; z-index: 300;
  width: 380px; height: 520px; max-height: calc(100vh - 8rem);
  background: var(--surface); border: 1px solid var(--border); border-radius: 20px;
  box-shadow: var(--shadow); flex-direction: column; overflow: hidden;
  animation: chatSlideUp 0.3s ease;
}
.chat-popup.open { display: flex; }
@keyframes chatSlideUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
.chat-header { padding: 1rem 1.2rem; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 0.6rem; }
.chat-header h3 { font-size: 0.82rem; font-weight: 700; flex: 1; }
.chat-badge { font-size: 0.55rem; padding: 0.2rem 0.5rem; background: var(--accent-glow); color: var(--accent); border-radius: 4px; font-weight: 700; text-transform: uppercase; }
.chat-close-btn { background: none; border: none; color: var(--muted); font-size: 1.1rem; cursor: pointer; padding: 0.2rem; transition: color 0.2s; }
.chat-close-btn:hover { color: var(--text); }

.chat-messages { flex: 1; overflow-y: auto; padding: 1rem 1.2rem; display: flex; flex-direction: column; gap: 0.8rem; }
.chat-messages::-webkit-scrollbar { width: 4px; }
.chat-messages::-webkit-scrollbar-thumb { background: var(--surface3); border-radius: 2px; }
.chat-msg { max-width: 90%; padding: 0.7rem 1rem; border-radius: 12px; font-size: 0.78rem; line-height: 1.5; animation: fadeIn 0.2s ease; word-wrap: break-word; }
.chat-msg.user { background: var(--accent); color: #fff; align-self: flex-end; border-bottom-right-radius: 4px; }
.chat-msg.agent { background: var(--surface2); color: var(--text2); align-self: flex-start; border-bottom-left-radius: 4px; border: 1px solid var(--border); }
.chat-msg.agent pre { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 0.5rem; margin: 0.4rem 0; overflow-x: auto; font-size: 0.72rem; }
.chat-msg.agent code { font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; background: var(--surface); padding: 0.1rem 0.3rem; border-radius: 3px; }
.chat-msg.typing .dots { display: inline-flex; gap: 3px; }
.chat-msg.typing .dots span { width: 5px; height: 5px; background: var(--muted); border-radius: 50%; animation: bounce 1.4s ease-in-out infinite; }
.chat-msg.typing .dots span:nth-child(2) { animation-delay: 0.2s; }
.chat-msg.typing .dots span:nth-child(3) { animation-delay: 0.4s; }
@keyframes bounce { 0%,80%,100% { transform: scale(0.6); } 40% { transform: scale(1); } }

.chat-input-area { padding: 0.8rem 1rem; border-top: 1px solid var(--border); display: flex; gap: 0.5rem; }
.chat-input {
  flex: 1; padding: 0.6rem 0.8rem; background: var(--bg); border: 1px solid var(--border);
  border-radius: 10px; color: var(--text); font-family: 'Inter', sans-serif; font-size: 0.78rem; outline: none;
  transition: border-color 0.2s; resize: none;
}
.chat-input:focus { border-color: var(--accent); }
.chat-send { padding: 0.6rem 0.9rem; background: var(--accent); border: none; border-radius: 10px; color: #fff; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
.chat-send:hover { background: var(--accent2); }
.chat-send:disabled { opacity: 0.4; cursor: not-allowed; }

/* ── Source badges ── */
.source-row { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
.src-badge { padding: 0.4rem 0.8rem; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; font-size: 0.72rem; color: var(--muted); }
.src-badge b { color: var(--text); }

/* ── Empty state ── */
.empty-state { text-align: center; padding: 6rem 2rem; }
.empty-orb {
  width: 80px; height: 80px; margin: 0 auto 2rem; border-radius: 50%; position: relative;
  background: radial-gradient(circle at 35% 35%, var(--accent-glow), transparent 70%);
  border: 1px solid var(--border);
}
.empty-orb::after { content: ''; position: absolute; inset: 8px; border-radius: 50%; border: 1px solid var(--accent-glow); animation: orbPulse 3s ease-in-out infinite; }
@keyframes orbPulse { 0%,100% { transform: scale(1); opacity: 0.5; } 50% { transform: scale(1.15); opacity: 1; } }
.empty-state h2 { font-size: 1.2rem; font-weight: 700; margin-bottom: 0.6rem; }
.empty-state p { color: var(--muted); font-size: 0.82rem; max-width: 420px; margin: 0 auto; line-height: 1.6; }

/* ── Jira ── */
.jira-section { margin-top: 1.5rem; padding-top: 1.2rem; border-top: 1px solid var(--border); display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }
.jira-btn {
  padding: 0.6rem 1.4rem; background: #0052cc; border: none; border-radius: 8px; color: #fff;
  font-family: 'Inter', sans-serif; font-size: 0.78rem; font-weight: 600; cursor: pointer;
  transition: all 0.2s; display: inline-flex; align-items: center; gap: 0.4rem;
}
.jira-btn:hover { background: #0747a6; transform: translateY(-1px); }
.jira-status { font-size: 0.78rem; }
.jira-confirm { display: inline-flex; align-items: center; gap: 0.6rem; padding: 0.5rem 0.8rem; background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; font-size: 0.78rem; }
.jira-approve { padding: 0.35rem 0.8rem; background: #0052cc; border: none; border-radius: 6px; color: #fff; font-size: 0.72rem; font-weight: 600; cursor: pointer; font-family: 'Inter', sans-serif; }
.jira-approve:hover { background: #0747a6; }
.jira-cancel { padding: 0.35rem 0.8rem; background: var(--surface3); border: 1px solid var(--border); border-radius: 6px; color: var(--muted); font-size: 0.72rem; cursor: pointer; font-family: 'Inter', sans-serif; }
.jira-cancel:hover { color: var(--text); border-color: var(--text); }
.jira-pending { color: var(--accent); }
.jira-success { color: var(--green); }
.jira-success a { color: var(--green); text-decoration: underline; }
.jira-error { color: var(--critical); font-size: 0.75rem; }

/* ── Bulk Jira ── */
.bulk-jira-bar {
  display: none; margin-bottom: 1.5rem; padding: 1rem 1.2rem; background: var(--surface);
  border: 1px solid var(--critical-border); border-radius: 14px;
  align-items: center; gap: 1rem; flex-wrap: wrap;
}
.bulk-jira-bar.visible { display: flex; animation: slideDown 0.3s ease; }
.bulk-jira-info { flex: 1; font-size: 0.82rem; color: var(--text2); }
.bulk-jira-info b { color: var(--critical); }
.bulk-jira-btn {
  padding: 0.65rem 1.6rem; background: linear-gradient(135deg, #0052cc, #0747a6); border: none; border-radius: 10px;
  color: #fff; font-family: 'Inter', sans-serif; font-size: 0.8rem; font-weight: 700; cursor: pointer;
  transition: all 0.3s; display: inline-flex; align-items: center; gap: 0.5rem;
}
.bulk-jira-btn:hover { transform: translateY(-2px); box-shadow: 0 4px 20px rgba(0,82,204,0.3); }
.bulk-jira-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
.bulk-jira-results { width: 100%; margin-top: 0.5rem; font-size: 0.78rem; }
.bulk-jira-results .ticket-row { display: flex; align-items: center; gap: 0.6rem; padding: 0.4rem 0; border-bottom: 1px solid var(--border); }
.bulk-jira-results .ticket-row:last-child { border-bottom: none; }
.bulk-jira-results .ticket-ok { color: var(--green); }
.bulk-jira-results .ticket-err { color: var(--critical); }
.bulk-jira-results a { color: var(--accent); text-decoration: underline; }
.bulk-jira-progress { width: 100%; height: 3px; background: var(--surface3); border-radius: 2px; margin-top: 0.5rem; overflow: hidden; display: none; }
.bulk-jira-progress.active { display: block; }
.bulk-jira-progress .bar { height: 100%; background: linear-gradient(90deg, #0052cc, var(--accent)); border-radius: 2px; transition: width 0.3s; }

/* ── Auto-fix section ── */
.autofix-section {
  display: none; margin-top: 2rem; padding: 1.5rem; background: var(--surface);
  border: 1px solid var(--border); border-radius: 16px;
}
.autofix-section.visible { display: block; animation: slideDown 0.3s ease; }
.autofix-header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; }
.autofix-header h3 { font-size: 1rem; font-weight: 700; flex: 1; }
.autofix-btn {
  padding: 0.7rem 1.6rem; background: linear-gradient(135deg, var(--green), #00a854); border: none; border-radius: 10px;
  color: #fff; font-family: 'Inter', sans-serif; font-size: 0.82rem; font-weight: 700; cursor: pointer;
  transition: all 0.3s; display: inline-flex; align-items: center; gap: 0.5rem;
}
.autofix-btn:hover { transform: translateY(-2px); box-shadow: 0 4px 20px rgba(0,230,118,0.2); }
.autofix-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
.autofix-desc { font-size: 0.78rem; color: var(--muted); margin-bottom: 1rem; }
.autofix-jira-list { display: flex; flex-direction: column; gap: 0.4rem; margin-bottom: 1rem; max-height: 300px; overflow-y: auto; }
.autofix-jira-item {
  display: flex; align-items: center; gap: 0.75rem; padding: 0.7rem 1rem; background: var(--surface2);
  border: 1px solid var(--border); border-radius: 10px; font-size: 0.78rem;
}
.autofix-jira-item .jira-key { font-family: 'JetBrains Mono', monospace; color: var(--accent); font-weight: 600; min-width: 80px; }
.autofix-jira-item .jira-summary { flex: 1; }
.autofix-jira-item .jira-status { font-size: 0.65rem; padding: 0.15rem 0.5rem; background: var(--surface3); border-radius: 4px; color: var(--muted); font-weight: 600; text-transform: uppercase; }
.autofix-results { margin-top: 1rem; }
.autofix-results .fix-row { display: flex; align-items: center; gap: 0.6rem; padding: 0.5rem 0; border-bottom: 1px solid var(--border); font-size: 0.78rem; }
.autofix-results .fix-row:last-child { border-bottom: none; }
.autofix-results .fix-ok { color: var(--green); }
.autofix-results .fix-skip { color: var(--muted); }
.autofix-results .fix-fail { color: var(--critical); }
.autofix-pr { margin-top: 1rem; padding: 0.8rem 1rem; background: var(--green-bg); border: 1px solid rgba(0,230,118,0.2); border-radius: 10px; font-size: 0.82rem; }
.autofix-pr a { color: var(--green); font-weight: 600; text-decoration: underline; }
.autofix-progress { width: 100%; height: 3px; background: var(--surface3); border-radius: 2px; margin-top: 0.5rem; overflow: hidden; display: none; }
.autofix-progress.active { display: block; }
.autofix-progress .bar { height: 100%; background: linear-gradient(90deg, var(--green), var(--accent)); border-radius: 2px; transition: width 0.5s; }

/* ── Responsive ── */
@media (max-width: 900px) {
  .severity-grid { grid-template-columns: repeat(3, 1fr); }
  .chat-popup { width: calc(100vw - 2rem); right: 1rem; }
}
@media (max-width: 600px) {
  .severity-grid { grid-template-columns: repeat(2, 1fr); }
  .content-area { padding: 1rem; }
  .chat-popup { width: calc(100vw - 1rem); right: 0.5rem; bottom: 5rem; }
}
</style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <div class="logo">&#128737;</div>
    <h1>SecScan Agent</h1>
    <div class="header-actions">
      <span class="theme-label" id="themeLabel">Dark</span>
      <div class="theme-toggle" onclick="toggleTheme()" title="Toggle theme"></div>
    </div>
  </div>
</div>

<div class="main-layout">
  <div class="content-area">
    <!-- Scan -->
    <div class="scan-section">
      <div class="scan-form">
        <input type="text" id="repoInput" placeholder="https://github.com/user/repo" onkeydown="if(event.key==='Enter')startScan()" />
        <button class="scan-btn" id="scanBtn" onclick="startScan()">Scan</button>
      </div>
    </div>

    <!-- Pipeline -->
    <div class="pipeline" id="pipeline">
      <div class="pipeline-label">Agent Pipeline</div>
      <div class="pipeline-row">
        <div class="pnode" id="pn-clone">Clone</div>
        <span class="parrow">&rarr;</span>
        <span class="pbracket">[</span>
        <div class="pnode" id="pn-bandit">Bandit</div>
        <div class="pnode" id="pn-pattern">Pattern</div>
        <div class="pnode" id="pn-ai">AI</div>
        <span class="pbracket">]</span>
        <span class="parrow">&rarr;</span>
        <div class="pnode" id="pn-classify">Classify</div>
      </div>
    </div>

    <!-- Status -->
    <div class="status-bar" id="statusBar"><div class="status-dot"></div><span id="statusText"></span></div>

    <!-- Results -->
    <div id="resultsArea" style="display:none;">
      <div class="severity-grid" id="sevGrid"></div>
      <div class="source-row" id="sourceRow"></div>
      <div class="bulk-jira-bar" id="bulkJiraBar">
        <span class="bulk-jira-info" id="bulkJiraInfo"></span>
        <button class="bulk-jira-btn" id="bulkJiraBtn" onclick="bulkJiraConfirm()">Raise All Critical in Jira</button>
        <div class="bulk-jira-progress" id="bulkJiraProgress"><div class="bar" id="bulkJiraProgressBar" style="width:0%"></div></div>
        <div class="bulk-jira-results" id="bulkJiraResults"></div>
      </div>
      <div class="vuln-section" id="vulnSection">
        <div class="vuln-section-header">
          <div class="vuln-section-title" id="vulnSectionTitle"></div>
          <button class="vuln-close" onclick="closeVulnList()">&times; Close</button>
        </div>
        <div class="vuln-list" id="vulnList"></div>
      </div>
    </div>

    <!-- Auto-fix section -->
    <div class="autofix-section" id="autofixSection">
      <div class="autofix-header">
        <h3>Auto-Fix Agent</h3>
        <button class="autofix-btn" id="autofixBtn" onclick="runAutofix()">Fix All Issues &amp; Raise PR</button>
      </div>
      <p class="autofix-desc">The agent will fetch open security tickets from Jira, generate fixes for CRITICAL and HIGH vulnerabilities, commit the changes, and raise a Pull Request.</p>
      <div id="autofixJiraList" class="autofix-jira-list"></div>
      <div class="autofix-progress" id="autofixProgress"><div class="bar" id="autofixProgressBar" style="width:0%"></div></div>
      <div class="autofix-results" id="autofixResults"></div>
    </div>

    <!-- Empty -->
    <div class="empty-state" id="emptyState">
      <div class="empty-orb"></div>
      <h2>Ready to scan</h2>
      <p>Paste a Git repo URL or local path. The agent clones the repo, then runs Bandit, pattern matching, and AI review in parallel.</p>
    </div>
  </div>
</div>

<!-- Inspect overlay -->
<div class="inspect-overlay" id="inspectOverlay" onclick="if(event.target===this)closeInspect()">
  <div class="inspect-panel" id="inspectPanel"></div>
</div>

<!-- Floating chat popup -->
<button class="chat-fab" id="chatFab" onclick="toggleChat()" title="Chat with Security Agent">&#128172;</button>
<div class="chat-popup" id="chatPopup">
  <div class="chat-header">
    <h3>Security Agent</h3>
    <span class="chat-badge">AI</span>
    <button class="chat-close-btn" onclick="toggleChat()">&times;</button>
  </div>
  <div class="chat-messages" id="chatMessages">
    <div class="chat-msg agent">Hi! I'm your security assistant. Scan a repo and ask me anything about the findings.</div>
  </div>
  <div class="chat-input-area">
    <input class="chat-input" id="chatInput" placeholder="Ask about vulnerabilities..." onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendChat()}" />
    <button class="chat-send" id="chatSend" onclick="sendChat()">&#10148;</button>
  </div>
</div>

<script>
let scanData = null;
let allVulns = [];
let activeCard = null;

/* ── Theme ── */
function toggleTheme() {
  const html = document.documentElement;
  const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  document.getElementById('themeLabel').textContent = next === 'dark' ? 'Dark' : 'Light';
  localStorage.setItem('theme', next);
}
(function() {
  const saved = localStorage.getItem('theme');
  if (saved) { document.documentElement.setAttribute('data-theme', saved); document.getElementById('themeLabel').textContent = saved === 'dark' ? 'Dark' : 'Light'; }
})();

/* ── Status ── */
function setStatus(msg, type) {
  const bar = document.getElementById('statusBar');
  document.getElementById('statusText').textContent = msg;
  bar.className = 'status-bar visible ' + type;
}

/* ── Pipeline animation ── */
function setPNode(id, cls) { document.getElementById('pn-'+id).className = 'pnode '+cls; }
function resetPipeline() {
  document.getElementById('pipeline').classList.add('visible');
  ['clone','bandit','pattern','ai','classify'].forEach(n => setPNode(n, ''));
}
function animatePipeline() {
  setPNode('clone', 'running');
  setTimeout(() => { setPNode('clone', 'done'); setPNode('bandit', 'running'); setPNode('pattern', 'running'); setPNode('ai', 'running'); }, 1200);
}
function finishPipeline(data) {
  const src = data.summary.sources || {};
  setPNode('bandit', 'done'); setPNode('pattern', 'done'); setPNode('ai', 'done');
  setPNode('classify', 'running');
  setTimeout(() => setPNode('classify', 'done'), 400);
}

/* ── Scan ── */
async function startScan() {
  const url = document.getElementById('repoInput').value.trim();
  if (!url) return;
  const btn = document.getElementById('scanBtn');
  btn.disabled = true; btn.textContent = 'Scanning...';
  document.getElementById('emptyState').style.display = 'none';
  document.getElementById('resultsArea').style.display = 'none';
  closeVulnList();
  resetPipeline();
  setStatus('Agent started \u2014 cloning repository...', 'scanning');
  animatePipeline();

  try {
    const resp = await fetch('/api/scan', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({repo_url: url}) });
    const data = await resp.json();
    if (data.error) { setStatus('Error: ' + data.error, 'error'); ['clone','bandit','pattern','ai','classify'].forEach(n => { const el = document.getElementById('pn-'+n); if (el.classList.contains('running')) setPNode(n, 'error'); }); }
    else {
      scanData = data;
      allVulns = data.vulnerabilities || [];
      finishPipeline(data);
      renderResults(data);
      setStatus('Done \u2014 ' + data.summary.total + ' vulnerabilities found', 'done');
    }
  } catch(e) { setStatus('Network error: ' + e.message, 'error'); }
  finally { btn.disabled = false; btn.textContent = 'Scan'; }
}

/* ── Render severity cards ── */
function renderResults(data) {
  const s = data.summary;
  const src = s.sources || {};
  document.getElementById('resultsArea').style.display = 'block';

  const cards = [
    { key: 'total', label: 'Total', val: s.total, cls: 's-total', filter: 'ALL' },
    { key: 'critical', label: 'Critical', val: s.critical, cls: 's-critical', filter: 'CRITICAL' },
    { key: 'high', label: 'High', val: s.high, cls: 's-high', filter: 'HIGH' },
    { key: 'medium', label: 'Medium', val: s.medium, cls: 's-medium', filter: 'MEDIUM' },
    { key: 'low', label: 'Low', val: s.low, cls: 's-low', filter: 'LOW' },
  ];
  document.getElementById('sevGrid').innerHTML = cards.map(c =>
    `<div class="sev-card ${c.cls}" onclick="toggleSeverity('${c.filter}', this)" data-filter="${c.filter}"><div class="num">${c.val}</div><div class="lbl">${c.label}</div></div>`
  ).join('');

  document.getElementById('sourceRow').innerHTML =
    `<div class="src-badge">Bandit: <b>${src.bandit||0}</b></div>` +
    `<div class="src-badge">Pattern: <b>${src.pattern||0}</b></div>` +
    `<div class="src-badge">AI: <b>${src.ai||0}</b></div>`;

  // Show bulk Jira bar if critical issues exist
  const bulkBar = document.getElementById('bulkJiraBar');
  const bulkBtn = document.getElementById('bulkJiraBtn');
  const bulkInfo = document.getElementById('bulkJiraInfo');
  const bulkResults = document.getElementById('bulkJiraResults');
  if (s.critical > 0) {
    bulkInfo.innerHTML = '<b>' + s.critical + ' critical</b> vulnerabilities found. Raise Jira tickets for all of them at once.';
    bulkBtn.textContent = 'Raise All Critical in Jira';
    bulkBtn.style.background = 'linear-gradient(135deg, #0052cc, #0747a6)';
    bulkBtn.disabled = false;
    bulkBtn.dataset.state = '';
    bulkResults.innerHTML = '';
    bulkBar.classList.add('visible');
  } else {
    bulkBar.classList.remove('visible');
  }

  // Show auto-fix section if there are CRITICAL or HIGH issues
  const critHigh = s.critical + s.high;
  const autofixSec = document.getElementById('autofixSection');
  if (critHigh > 0) {
    autofixSec.classList.add('visible');
    document.getElementById('autofixBtn').disabled = false;
    document.getElementById('autofixBtn').textContent = 'Fix All Issues & Raise PR';
    document.getElementById('autofixBtn').style.background = 'linear-gradient(135deg, var(--green), #00a854)';
    document.getElementById('autofixResults').innerHTML = '';
    loadJiraTickets();
  } else {
    autofixSec.classList.remove('visible');
  }
}

/* ── Toggle severity list ── */
function toggleSeverity(filter, el) {
  const sec = document.getElementById('vulnSection');
  // If same card clicked, close
  if (activeCard === el && sec.classList.contains('visible')) { closeVulnList(); return; }
  // Deselect old
  document.querySelectorAll('.sev-card').forEach(c => c.classList.remove('active'));
  el.classList.add('active');
  activeCard = el;

  const filtered = filter === 'ALL' ? allVulns : allVulns.filter(v => v.severity === filter);
  const title = filter === 'ALL' ? `All Vulnerabilities (${filtered.length})` : `${filter} (${filtered.length})`;
  document.getElementById('vulnSectionTitle').textContent = title;
  document.getElementById('vulnList').innerHTML = filtered.length ? filtered.map(v =>
    `<div class="vuln-item" onclick='inspectIssue(${JSON.stringify(v).replace(/'/g,"&#39;")})'>
      <div class="sev-dot ${v.severity}"></div>
      <div class="vuln-item-title">${esc(v.title)}</div>
      <div class="vuln-item-file">${esc(v.file)}:${v.line}</div>
      <div class="vuln-item-src">${v.source}</div>
    </div>`
  ).join('') : '<div style="padding:1rem;color:var(--muted);font-size:0.82rem;">No issues at this severity.</div>';
  sec.classList.add('visible');
}

function closeVulnList() {
  document.getElementById('vulnSection').classList.remove('visible');
  document.querySelectorAll('.sev-card').forEach(c => c.classList.remove('active'));
  activeCard = null;
}

/* ── Inspect issue ── */
async function inspectIssue(vuln) {
  const overlay = document.getElementById('inspectOverlay');
  const panel = document.getElementById('inspectPanel');
  overlay.classList.add('visible');

  panel.innerHTML = `
    <div class="inspect-header">
      <span class="inspect-sev ${vuln.severity}">${vuln.severity}</span>
      <span class="inspect-title">${esc(vuln.title)}</span>
      <button class="inspect-close" onclick="closeInspect()">&times;</button>
    </div>
    <div class="inspect-meta">
      <span class="file-link">${esc(vuln.file)}:${vuln.line}</span>
      <span>Source: ${vuln.source}</span>
      <span>Confidence: ${vuln.confidence || 'N/A'}</span>
    </div>
    <div class="inspect-loading"><div class="spinner"></div><br>Analyzing vulnerability...</div>`;
  // Store vuln on overlay for Jira
  document.getElementById('inspectOverlay')._vuln = vuln;
  document.getElementById('inspectOverlay')._inspectData = null;

  try {
    const resp = await fetch('/api/inspect', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({vulnerability: vuln}) });
    const data = await resp.json();
    renderInspect(vuln, data, panel);
  } catch(e) {
    panel.querySelector('.inspect-loading').innerHTML = '<p style="color:var(--critical)">Failed to inspect: '+esc(e.message)+'</p>';
  }
}

function renderInspect(vuln, data, panel) {
  const body = panel.querySelector('.inspect-loading');
  if (!body) return;
  // Store inspect data for Jira
  document.getElementById('inspectOverlay')._inspectData = data;
  let html = '<div class="inspect-body">';
  html += '<h3>Explanation</h3><p>' + esc(data.explanation || vuln.description || 'N/A') + '</p>';
  if (data.impact) html += '<h3>Impact</h3><p>' + esc(data.impact) + '</p>';
  if (data.fix_steps && data.fix_steps.length) {
    html += '<h3>Steps to Fix</h3><ol>' + data.fix_steps.map(s => '<li>'+esc(s)+'</li>').join('') + '</ol>';
  }
  if (data.code_before) html += '<h3>Vulnerable Code</h3><pre>' + esc(data.code_before) + '</pre>';
  if (data.code_after) html += '<h3>Fixed Code</h3><pre>' + esc(data.code_after) + '</pre>';
  if (data.prevention) html += '<h3>Prevention</h3><p>' + esc(data.prevention) + '</p>';
  html += '</div>';
  // Jira button
  html += `<div class="jira-section">
    <button class="jira-btn" onclick="confirmJiraTicket()">Create Jira Ticket</button>
    <span class="jira-status" id="jiraStatus"></span>
  </div>`;
  body.outerHTML = html;
}

/* ── Jira ticket creation with approval ── */
function confirmJiraTicket() {
  const overlay = document.getElementById('inspectOverlay');
  const vuln = overlay._vuln;
  if (!vuln) return;

  // Show approval dialog
  const status = document.getElementById('jiraStatus');
  status.innerHTML = `
    <span class="jira-confirm">
      <span>Create a Jira ticket for "<b>${esc(vuln.title)}</b>"?</span>
      <button class="jira-approve" onclick="createJiraTicket()">Approve</button>
      <button class="jira-cancel" onclick="document.getElementById('jiraStatus').innerHTML=''">Cancel</button>
    </span>`;
}

async function createJiraTicket() {
  const overlay = document.getElementById('inspectOverlay');
  const vuln = overlay._vuln;
  const inspectData = overlay._inspectData;
  const status = document.getElementById('jiraStatus');
  if (!vuln) return;

  status.innerHTML = '<span class="jira-pending">Creating ticket...</span>';

  try {
    const resp = await fetch('/api/jira', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ vulnerability: vuln, inspect_data: inspectData || {} }),
    });
    const data = await resp.json();
    if (data.error) {
      status.innerHTML = '<span class="jira-error">' + esc(data.error) + '</span>';
    } else {
      status.innerHTML = `<span class="jira-success">Ticket created: <a href="${esc(data.url)}" target="_blank" rel="noopener">${esc(data.key)}</a></span>`;
    }
  } catch(e) {
    status.innerHTML = '<span class="jira-error">Network error: ' + esc(e.message) + '</span>';
  }
}

function closeInspect() { document.getElementById('inspectOverlay').classList.remove('visible'); }

/* ── Chat ── */
async function sendChat() {
  const input = document.getElementById('chatInput');
  const msg = input.value.trim();
  if (!msg) return;
  input.value = '';

  const messages = document.getElementById('chatMessages');
  messages.innerHTML += `<div class="chat-msg user">${esc(msg)}</div>`;
  messages.innerHTML += `<div class="chat-msg agent typing" id="typingMsg"><div class="dots"><span></span><span></span><span></span></div></div>`;
  messages.scrollTop = messages.scrollHeight;

  document.getElementById('chatSend').disabled = true;

  try {
    const resp = await fetch('/api/chat', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({message: msg}) });
    const data = await resp.json();
    const typing = document.getElementById('typingMsg');
    if (typing) typing.outerHTML = `<div class="chat-msg agent">${formatAgentMsg(data.reply)}</div>`;
  } catch(e) {
    const typing = document.getElementById('typingMsg');
    if (typing) typing.outerHTML = `<div class="chat-msg agent" style="color:var(--critical)">Error: ${esc(e.message)}</div>`;
  }
  document.getElementById('chatSend').disabled = false;
  messages.scrollTop = messages.scrollHeight;
}

function formatAgentMsg(text) {
  // Basic markdown: code blocks, inline code, bold
  let s = esc(text);
  s = s.replace(/```(\w*)\n?([\s\S]*?)```/g, '<pre>$2</pre>');
  s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
  s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/\n/g, '<br>');
  return s;
}

function toggleChat() {
  const popup = document.getElementById('chatPopup');
  popup.classList.toggle('open');
}

/* ── Bulk Jira ── */
function bulkJiraConfirm() {
  const critCount = scanData ? scanData.summary.critical : 0;
  if (!critCount) return;
  const btn = document.getElementById('bulkJiraBtn');
  const info = document.getElementById('bulkJiraInfo');
  // Toggle to confirm state
  if (btn.dataset.state !== 'confirm') {
    btn.dataset.state = 'confirm';
    btn.textContent = 'Confirm — Create ' + critCount + ' Tickets';
    btn.style.background = 'linear-gradient(135deg, #e0301e, #b71c1c)';
    info.innerHTML = '&#9888; This will create <b>' + critCount + ' Jira tickets</b> for all CRITICAL vulnerabilities.';
    return;
  }
  // Actually create
  bulkJiraCreate();
}

async function bulkJiraCreate() {
  const btn = document.getElementById('bulkJiraBtn');
  const results = document.getElementById('bulkJiraResults');
  const progress = document.getElementById('bulkJiraProgress');
  const bar = document.getElementById('bulkJiraProgressBar');

  btn.disabled = true;
  btn.textContent = 'Creating tickets...';
  results.innerHTML = '';
  progress.classList.add('active');
  bar.style.width = '30%';

  try {
    bar.style.width = '60%';
    const resp = await fetch('/api/jira/bulk', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ severity: 'CRITICAL' }),
    });
    const data = await resp.json();
    bar.style.width = '100%';

    if (data.error) {
      results.innerHTML = '<div class="ticket-err">' + esc(data.error) + '</div>';
    } else {
      let html = '';
      if (data.created && data.created.length) {
        html += data.created.map(t =>
          `<div class="ticket-row"><span class="ticket-ok">&#10003;</span> <b>${esc(t.vuln_id)}</b> ${esc(t.title)} &rarr; <a href="${esc(t.url)}" target="_blank" rel="noopener">${esc(t.key)}</a></div>`
        ).join('');
      }
      if (data.errors && data.errors.length) {
        html += data.errors.map(t =>
          `<div class="ticket-row"><span class="ticket-err">&#10007;</span> <b>${esc(t.vuln_id)}</b> ${esc(t.title)} &mdash; ${esc(t.error)}</div>`
        ).join('');
      }
      results.innerHTML = html || '<div class="ticket-ok">No critical issues to report.</div>';
      btn.textContent = data.success_count + '/' + data.total + ' tickets created';
      btn.style.background = 'linear-gradient(135deg, #00a854, #007a3d)';
    }
  } catch(e) {
    results.innerHTML = '<div class="ticket-err">Network error: ' + esc(e.message) + '</div>';
  }

  setTimeout(() => progress.classList.remove('active'), 1000);
  btn.disabled = true;
  btn.dataset.state = 'done';
}

/* ── Auto-fix agent ── */
async function loadJiraTickets() {
  const list = document.getElementById('autofixJiraList');
  list.innerHTML = '<div style="color:var(--muted);font-size:0.78rem;padding:0.5rem;">Loading Jira tickets...</div>';
  try {
    const resp = await fetch('/api/jira/tickets');
    const data = await resp.json();
    if (data.tickets && data.tickets.length) {
      list.innerHTML = data.tickets.map(t =>
        `<div class="autofix-jira-item">
          <span class="jira-key">${esc(t.key)}</span>
          <span class="jira-summary">${esc(t.summary)}</span>
          <span class="jira-status">${esc(t.status)}</span>
        </div>`
      ).join('');
    } else {
      list.innerHTML = '<div style="color:var(--muted);font-size:0.78rem;padding:0.5rem;">No open security tickets found in Jira.</div>';
    }
  } catch(e) {
    list.innerHTML = '<div style="color:var(--critical);font-size:0.78rem;padding:0.5rem;">Failed to load Jira tickets.</div>';
  }
}

async function runAutofix() {
  if (!scanData || !scanData.vulnerabilities || !scanData.vulnerabilities.length) return;
  const btn = document.getElementById('autofixBtn');
  const results = document.getElementById('autofixResults');
  const progress = document.getElementById('autofixProgress');
  const bar = document.getElementById('autofixProgressBar');

  btn.disabled = true;
  btn.textContent = 'Fixing issues...';
  results.innerHTML = '';
  progress.classList.add('active');
  bar.style.width = '10%';

  try {
    bar.style.width = '30%';
    const resp = await fetch('/api/autofix', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ repo_url: scanData.repo_url, vulnerabilities: scanData.vulnerabilities }),
    });
    bar.style.width = '80%';
    const data = await resp.json();
    bar.style.width = '100%';

    if (data.error && !data.fixes) {
      results.innerHTML = '<div class="fix-fail">' + esc(data.error) + '</div>';
    } else {
      let html = '';
      if (data.fixes && data.fixes.length) {
        html += data.fixes.map(f => {
          const icon = f.status === 'fixed' ? '<span class="fix-ok">&#10003;</span>' :
                       f.status === 'failed' ? '<span class="fix-fail">&#10007;</span>' :
                       '<span class="fix-skip">&#8212;</span>';
          const detail = f.status === 'fixed' ? esc(f.summary || '') : esc(f.reason || '');
          return `<div class="fix-row">${icon} <b>${esc(f.vuln_id || '')}</b> ${esc(f.title || '')} ${f.file ? 'in <code>'+esc(f.file)+'</code>' : ''} <span style="color:var(--muted);margin-left:auto;">${detail}</span></div>`;
        }).join('');
      }
      if (data.pr_url) {
        html += `<div class="autofix-pr">Pull Request created: <a href="${esc(data.pr_url)}" target="_blank" rel="noopener">${esc(data.pr_url)}</a></div>`;
      }
      if (data.message) {
        html += `<div style="margin-top:0.5rem;font-size:0.78rem;color:var(--text2);">${esc(data.message)}</div>`;
      }
      results.innerHTML = html;
      btn.textContent = (data.fixed_count || 0) + ' issues fixed';
      btn.style.background = 'linear-gradient(135deg, #00a854, #007a3d)';
    }
  } catch(e) {
    results.innerHTML = '<div class="fix-fail">Network error: ' + esc(e.message) + '</div>';
  }

  setTimeout(() => progress.classList.remove('active'), 1000);
  btn.disabled = false;
}

function esc(s) { const d = document.createElement('div'); d.textContent = s||''; return d.innerHTML; }
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    global _latest_scan
    data = request.get_json(force=True)
    repo_url = data.get("repo_url", "").strip()
    if not repo_url:
        return jsonify({"error": "repo_url is required"}), 400

    try:
        result = run_scan(repo_url)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    if result.get("error"):
        return jsonify({"error": result["error"]}), 400

    response = {
        "repo_url": repo_url,
        "summary": result.get("summary", {}),
        "vulnerabilities": result.get("vulnerabilities", []),
        "agent_trace": result.get("agent_trace", []),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
    _latest_scan = response
    return jsonify(response)


@app.route("/api/chat", methods=["POST"])
def api_chat():
    data = request.get_json(force=True)
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"error": "message is required"}), 400

    reply = chat_with_agent(message, scan_context=_latest_scan or None)
    return jsonify({"reply": reply})


@app.route("/api/inspect", methods=["POST"])
def api_inspect():
    data = request.get_json(force=True)
    vuln = data.get("vulnerability", {})
    if not vuln:
        return jsonify({"error": "vulnerability is required"}), 400

    result = inspect_vulnerability(vuln, scan_context=_latest_scan or None)
    return jsonify(result)


@app.route("/api/jira", methods=["POST"])
def api_jira():
    data = request.get_json(force=True)
    vuln = data.get("vulnerability", {})
    inspect_data = data.get("inspect_data", {})
    if not vuln:
        return jsonify({"error": "vulnerability is required"}), 400

    result = create_jira_ticket(vuln, inspect_data=inspect_data if inspect_data else None)
    if result.get("error"):
        return jsonify(result), 400
    return jsonify(result)


@app.route("/api/jira/bulk", methods=["POST"])
def api_jira_bulk():
    data = request.get_json(force=True)
    severity = data.get("severity", "CRITICAL")
    vulns = data.get("vulnerabilities") or (_latest_scan.get("vulnerabilities") if _latest_scan else [])
    if not vulns:
        return jsonify({"error": "No scan data available. Run a scan first."}), 400

    result = create_jira_tickets_bulk(vulns, severity_filter=severity)
    return jsonify(result)


@app.route("/api/jira/tickets")
def api_jira_tickets():
    tickets = fetch_jira_security_tickets()
    return jsonify({"tickets": tickets})


@app.route("/api/autofix", methods=["POST"])
def api_autofix():
    data = request.get_json(force=True)
    repo_url = data.get("repo_url", "")
    vulns = data.get("vulnerabilities", [])
    if not repo_url:
        return jsonify({"error": "repo_url is required"}), 400
    if not vulns:
        return jsonify({"error": "No vulnerabilities provided"}), 400

    result = autofix_from_scan(repo_url, vulns)
    return jsonify(result)


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})

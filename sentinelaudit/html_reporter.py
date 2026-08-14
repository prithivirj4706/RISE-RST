"""Self-contained HTML audit report.

Design system derived from the `ui-ux-pro-max` skill for the brief
"security audit / compliance report / developer tool":

    style       Dark Mode (OLED) -- "Code dark + run green"
    background  #0F172A   card #1B2336   border #475569
    accent      #22C55E   destructive #EF4444   foreground #F8FAFC
    type        JetBrains Mono (evidence) / IBM Plex Sans (prose)
    motion      subtle scroll reveal, 300-400ms, power1.out

Two deliberate deviations from that recommendation, both for the same reason --
an audit report is evidence and must render identically anywhere, forever:

* **No webfont import.** The skill suggested a Google Fonts `@import`. A report
  about a locked-down host should not phone out to a CDN to render, and may well
  be read on an air-gapped machine. The stacks below name JetBrains Mono and IBM
  Plex Sans first and degrade to system fonts.
* **No GSAP / scroll-reveal library.** The motion recommendation needs an
  external script. Reveal is done in ~10 lines of CSS + IntersectionObserver,
  and is skipped entirely under `prefers-reduced-motion`.

The output is one file with zero external requests: no fonts, no scripts, no
images, no analytics. Open it from a USB stick on a disconnected laptop and it
looks the same.
"""

from __future__ import annotations

import html
import json
from typing import Any

from .models import CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, AuditReport

# --- design tokens, straight from the skill's design-system output ----------
TOKENS = """
  --bg:#0F172A; --card:#1B2336; --muted:#272F42; --border:#475569;
  --fg:#F8FAFC; --fg-muted:#94A3B8;
  --primary:#1E293B; --secondary:#334155;
  --accent:#22C55E; --on-accent:#0F172A;
  --critical:#EF4444; --high:#F97316; --medium:#EAB308; --low:#38BDF8;
  --ring:#F8FAFC;
  --mono:'JetBrains Mono','SF Mono',Menlo,Consolas,'Liberation Mono',monospace;
  --sans:'IBM Plex Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
"""

_SEV_VAR = {CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low"}

# Inline SVG only -- the skill's checklist forbids emoji-as-icon.
_ICON = {
    "pass": '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2.2" '
            'stroke-linecap="round" stroke-linejoin="round"><path d="M4 10.5l4 4 8-9"/></svg>',
    "fail": '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2.2" '
            'stroke-linecap="round"><path d="M5 5l10 10M15 5L5 15"/></svg>',
    "unknown": '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2.2" '
               'stroke-linecap="round" stroke-linejoin="round">'
               '<path d="M7.2 7.4a2.9 2.9 0 115.1 1.9c-.9.9-2.3 1.3-2.3 2.9"/>'
               '<circle cx="10" cy="15.4" r="1.1" fill="currentColor" stroke="none"/></svg>',
    "copy": '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" '
            'stroke-linecap="round" stroke-linejoin="round">'
            '<rect x="7" y="7" width="9" height="9" rx="1.6"/>'
            '<path d="M13 4.5H5.6A1.6 1.6 0 004 6.1V13"/></svg>',
    "lock": '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" '
            'stroke-linecap="round" stroke-linejoin="round">'
            '<rect x="4" y="9" width="12" height="8" rx="1.8"/>'
            '<path d="M7 9V6.6a3 3 0 016 0V9"/></svg>',
}

_STATUS_ICON = {PASS: "pass", FAIL: "fail", UNKNOWN: "unknown"}


def _e(text: Any) -> str:
    return html.escape(str(text if text is not None else ""), quote=True)


def _css() -> str:
    # NOTE: plain .replace, not %-formatting -- this CSS is full of
    # literal percent signs (100%, -8%) that would break a format string.
    return """
*,*::before,*::after{box-sizing:border-box}
:root{__TOKENS__}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);font-family:var(--sans);
  font-size:15px;line-height:1.6;-webkit-font-smoothing:antialiased}
.wrap{max-width:1080px;margin:0 auto;padding:40px 24px 96px}
h1,h2,h3{line-height:1.25;margin:0}
h2{font-size:13px;letter-spacing:.13em;text-transform:uppercase;color:var(--fg-muted);
  font-weight:600;margin:56px 0 18px;padding-bottom:10px;border-bottom:1px solid var(--muted)}
code,pre,.mono{font-family:var(--mono)}
a{color:var(--accent)}
:focus-visible{outline:2px solid var(--ring);outline-offset:3px;border-radius:4px}

/* ---- masthead ---- */
.mast{display:flex;flex-wrap:wrap;gap:20px;align-items:flex-start;
  justify-content:space-between;padding-bottom:26px;border-bottom:1px solid var(--muted)}
.brand{display:flex;align-items:center;gap:11px;font-weight:700;font-size:19px;letter-spacing:-.01em}
.brand svg{width:19px;height:19px;color:var(--accent)}
.meta{font-family:var(--mono);font-size:12px;color:var(--fg-muted);text-align:right;line-height:1.9}
.meta b{color:var(--fg);font-weight:500}

/* ---- score ---- */
.score-row{display:grid;grid-template-columns:minmax(210px,260px) 1fr;gap:20px;margin-top:28px}
@media(max-width:760px){.score-row{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--muted);border-radius:12px;padding:22px}
.score-card{display:flex;flex-direction:column;justify-content:center;align-items:center;
  text-align:center;gap:2px}
.score-num{font-family:var(--mono);font-size:66px;font-weight:700;line-height:1;
  letter-spacing:-.03em;color:var(--grade-c)}
.score-max{font-size:15px;color:var(--fg-muted);font-weight:400}
.grade{margin-top:10px;font-size:12px;letter-spacing:.1em;text-transform:uppercase;
  font-weight:600;padding:5px 12px;border-radius:999px;border:1px solid currentColor}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(96px,1fr));gap:10px}
.tile{background:var(--card);border:1px solid var(--muted);border-radius:10px;
  padding:14px 12px;border-left:3px solid var(--tc,var(--border))}
.tile .n{font-family:var(--mono);font-size:26px;font-weight:700;line-height:1;color:var(--tc,var(--fg))}
.tile .l{font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--fg-muted);
  margin-top:7px;font-weight:600}
.coverage{margin-top:12px;font-size:13px;color:var(--fg-muted)}
.warn{margin-top:14px;background:rgba(239,68,68,.09);border:1px solid var(--critical);
  border-left-width:3px;border-radius:8px;padding:13px 15px;font-size:13.5px;color:#FCA5A5}
.warn b{color:#FECACA}

/* ---- fingerprint ---- */
.fp{margin-top:14px;background:var(--muted);border:1px solid var(--border);border-radius:10px;
  padding:14px 16px;display:flex;gap:12px;align-items:flex-start}
.fp svg{width:16px;height:16px;color:var(--accent);flex:none;margin-top:2px}
.fp .t{font-size:13px;color:var(--fg-muted)}
.fp .h{font-family:var(--mono);font-size:11.5px;color:var(--fg);word-break:break-all;
  margin-top:5px;user-select:all}

/* ---- fix list ---- */
.fix{background:var(--card);border:1px solid var(--muted);border-radius:12px;
  border-left:3px solid var(--sc);padding:20px 22px;margin-bottom:14px}
.fix-head{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:12px}
.prio{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--bg);background:var(--sc);
  width:24px;height:24px;border-radius:6px;display:grid;place-items:center;flex:none}
.sev{font-size:10.5px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;
  color:var(--sc);border:1px solid var(--sc);border-radius:999px;padding:2.5px 9px}
.rid{font-family:var(--mono);font-size:12.5px;color:var(--fg-muted)}
.cat{font-size:12px;color:var(--fg-muted);margin-left:auto}
.fix h3{font-size:16.5px;font-weight:600;margin-bottom:9px}
.why{font-size:14px;color:#CBD5E1;margin:0 0 16px}
.lbl{font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--fg-muted);
  font-weight:600;margin-bottom:6px;display:flex;align-items:center;gap:8px}
.lbl .cmd{font-family:var(--mono);text-transform:none;letter-spacing:0;color:var(--fg-muted);
  font-size:11px;opacity:.85}
pre{margin:0 0 16px;background:var(--bg);border:1px solid var(--muted);border-radius:8px;
  padding:13px 15px;overflow-x:auto;font-size:12.5px;line-height:1.65;color:#E2E8F0;
  white-space:pre-wrap;word-break:break-word}
pre.fixcmd{background:rgba(34,197,94,.07);border-color:rgba(34,197,94,.4);color:#BBF7D0;margin-bottom:0}
.cmdbox{position:relative}
.copy{position:absolute;top:8px;right:8px;background:var(--muted);border:1px solid var(--border);
  color:var(--fg-muted);border-radius:6px;padding:5px 9px;font-size:11px;font-family:var(--sans);
  cursor:pointer;display:flex;align-items:center;gap:5px;transition:color .18s,border-color .18s,background .18s}
.copy svg{width:12px;height:12px}
.copy:hover{color:var(--accent);border-color:var(--accent);background:var(--bg)}
.copy.done{color:var(--accent);border-color:var(--accent)}
.ref{margin-top:12px;font-family:var(--mono);font-size:11px;color:var(--fg-muted)}

/* ---- tables ---- */
.tbl-wrap{overflow-x:auto;border:1px solid var(--muted);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:13px;min-width:660px}
th{text-align:left;font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;
  color:var(--fg-muted);font-weight:600;padding:11px 14px;background:var(--muted);
  border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:11px 14px;border-bottom:1px solid var(--muted);vertical-align:top}
tr:last-child td{border-bottom:none}
tbody tr{transition:background .16s}
tbody tr:hover{background:rgba(255,255,255,.028)}
td.rid-c{font-family:var(--mono);font-size:12px;white-space:nowrap}
td.ev{font-family:var(--mono);font-size:11.5px;color:var(--fg-muted);max-width:330px}
.st{display:inline-flex;align-items:center;gap:6px;font-weight:600;font-size:11.5px;white-space:nowrap}
.st svg{width:13px;height:13px}
.st.pass{color:var(--accent)} .st.fail{color:var(--critical)} .st.unknown{color:var(--medium)}

/* ---- unknown ---- */
.unk{background:var(--card);border:1px solid var(--muted);border-left:3px solid var(--medium);
  border-radius:10px;padding:15px 18px;margin-bottom:10px}
.unk .h{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;margin-bottom:6px}
.unk .r{font-size:13.5px;color:#CBD5E1}
.unk .c{font-family:var(--mono);font-size:11px;color:var(--fg-muted);margin-top:7px}

details{background:var(--card);border:1px solid var(--muted);border-radius:10px;padding:0}
summary{cursor:pointer;padding:14px 18px;font-size:13.5px;font-weight:600;list-style:none;
  display:flex;align-items:center;gap:9px;transition:color .18s}
summary:hover{color:var(--accent)}
summary::-webkit-details-marker{display:none}
summary::before{content:"";width:0;height:0;border-left:5px solid currentColor;
  border-top:4px solid transparent;border-bottom:4px solid transparent;transition:transform .2s}
details[open] summary::before{transform:rotate(90deg)}
.details-body{padding:0 18px 18px}
.notes{list-style:none;padding:0;margin:0;font-size:13px;color:var(--fg-muted)}
.notes li{padding:8px 0 8px 16px;border-bottom:1px solid var(--muted);position:relative}
.notes li:last-child{border-bottom:none}
.notes li::before{content:"";position:absolute;left:0;top:15px;width:5px;height:5px;
  border-radius:50%;background:var(--border)}
footer{margin-top:60px;padding-top:22px;border-top:1px solid var(--muted);
  font-size:12px;color:var(--fg-muted);display:flex;justify-content:space-between;
  gap:14px;flex-wrap:wrap}
.pill{display:inline-flex;align-items:center;gap:6px;background:var(--muted);
  border:1px solid var(--border);border-radius:999px;padding:3.5px 11px;
  font-family:var(--mono);font-size:11px;color:var(--fg-muted)}

/* ---- reveal (no library; disabled under reduced motion) ---- */
.rv{opacity:0;transform:translateY(12px);transition:opacity .35s cubic-bezier(.25,.46,.45,.94),
  transform .35s cubic-bezier(.25,.46,.45,.94)}
.rv.in{opacity:1;transform:none}
@media(prefers-reduced-motion:reduce){
  html{scroll-behavior:auto}
  .rv{opacity:1;transform:none;transition:none}
  *{transition-duration:.01ms!important;animation-duration:.01ms!important}
}
@media print{
  body{background:#fff;color:#000}
  .card,.fix,.unk,pre,.tbl-wrap{border-color:#ccc;background:#fff}
  .copy{display:none}
  .rv{opacity:1;transform:none}
}
""".replace("__TOKENS__", TOKENS)


def _grade_color(grade: str) -> str:
    return {
        "A": "var(--accent)", "B": "var(--accent)", "C": "var(--medium)",
        "D": "var(--high)", "F": "var(--critical)",
    }.get(grade, "var(--fg-muted)")


def render_html(report: AuditReport, feeds: dict[str, list[str]]) -> str:
    s = report.summary
    sc = report.score
    by_sev: dict[str, int] = sc and s["failed_by_severity"]  # type: ignore[assignment]
    grade = str(sc["grade"])
    gcol = _grade_color(grade)
    target = report.target

    out: list[str] = []
    w = out.append

    w("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    w('<meta name="viewport" content="width=device-width,initial-scale=1">')
    w('<meta name="robots" content="noindex,nofollow">')
    w(f"<title>SentinelAudit — {_e(target.get('label'))} — {sc['value']}/100</title>")
    w(f"<style>{_css()}</style>")
    # Without this, a viewer with JS disabled sees a blank page: every .rv
    # block starts at opacity:0 and only JS adds .in. Evidence must never
    # depend on scripting to be readable.
    w("<noscript><style>.rv{opacity:1!important;transform:none!important}</style></noscript>")
    w('</head><body><div class="wrap">')

    # -- masthead --------------------------------------------------------
    w('<header class="mast">')
    w(f'<div><div class="brand">{_ICON["lock"]}SentinelAudit</div>')
    w('<div style="font-size:13px;color:var(--fg-muted);margin-top:5px">'
      'Read-only, evidence-first security audit</div></div>')
    w('<div class="meta">')
    w(f'target <b>{_e(target.get("label"))}</b><br>')
    w(f'transport <b>{_e(target.get("transport"))}</b> &nbsp; platform <b>{_e(report.platform)}</b><br>')
    w(f'generated <b>{_e(report.generated_at)}</b>')
    w('</div></header>')

    # -- score + tiles ---------------------------------------------------
    w('<div class="score-row rv">')
    w(f'<div class="card score-card"><div class="score-num" style="color:{gcol}">'
      f'{sc["value"]}<span class="score-max">/100</span></div>'
      f'<div class="grade" style="color:{gcol}">{_e(grade)}</div></div>')
    w('<div><div class="tiles">')
    for sev, label in ((CRITICAL, "Critical"), (HIGH, "High"), (MEDIUM, "Medium"), (LOW, "Low")):
        n = by_sev[sev]
        col = f"var(--{_SEV_VAR[sev]})" if n else "var(--border)"
        w(f'<div class="tile" style="--tc:{col}"><div class="n">{n}</div>'
          f'<div class="l">{label}</div></div>')
    w(f'<div class="tile" style="--tc:var(--accent)"><div class="n">{s["passed"]}</div>'
      f'<div class="l">Passed</div></div>')
    w(f'<div class="tile" style="--tc:var(--fg-muted)"><div class="n">{s["unknown"]}</div>'
      f'<div class="l">Unknown</div></div>')
    w('</div>')
    w(f'<p class="coverage">{_e(sc["coverage_note"])}</p>')
    if not sc.get("sufficient_coverage", True):
        w('<div class="warn"><b>This score is not meaningful.</b> Only '
          f'{_e(sc["coverage_percent"])}% of the rule set was observable on this target, '
          'so no grade is issued. The number reflects what could be read, not the '
          'security of the host.</div>')
    w('</div></div>')

    # -- fingerprint -----------------------------------------------------
    w(f'<div class="fp rv">{_ICON["lock"]}<div><div class="t">'
      '<b style="color:var(--fg)">Report fingerprint</b> — SHA-256 over this entire report '
      'except the timestamp. Two runs against an unchanged target produce the same value, '
      'so reproducibility is a string comparison rather than a promise.</div>'
      f'<div class="h">{_e(report.fingerprint)}</div></div></div>')

    # -- fix list --------------------------------------------------------
    w('<h2>Prioritized remediation plan</h2>')
    if not report.fix_list:
        w('<div class="card rv" style="display:flex;gap:11px;align-items:center;color:var(--accent)">'
          f'<span style="width:18px;height:18px;display:block">{_ICON["pass"]}</span>'
          '<span style="color:var(--fg)">No failing checks on this target. Nothing to remediate.</span></div>')
    else:
        w('<p style="font-size:13.5px;color:var(--fg-muted);margin:-6px 0 18px">'
          'Ordered by severity, then rule ID. Every item traces to one rule, one command, '
          'and that command\'s captured output.</p>')
        for i, item in enumerate(report.fix_list):
            col = f"var(--{_SEV_VAR[item.severity]})"
            w(f'<article class="fix rv" style="--sc:{col}">')
            w('<div class="fix-head">')
            w(f'<span class="prio">{item.priority}</span>')
            w(f'<span class="sev">{_e(item.severity)}</span>')
            w(f'<span class="rid">{_e(item.rule_id)}</span>')
            w(f'<span class="cat">{_e(item.category)}</span>')
            w('</div>')
            w(f'<h3>{_e(item.finding)}</h3>')
            w(f'<p class="why">{_e(item.why_it_matters)}</p>')
            w(f'<div class="lbl">Evidence <span class="cmd">{_e(item.command)}</span></div>')
            w(f'<pre>{_e(item.evidence)}</pre>')
            w('<div class="lbl">Remediation</div>')
            w(f'<div class="cmdbox"><pre class="fixcmd" id="fx{i}">{_e(item.fix_command)}</pre>'
              f'<button class="copy" type="button" data-t="fx{i}" '
              f'aria-label="Copy remediation command for {_e(item.rule_id)}">'
              f'{_ICON["copy"]}<span>Copy</span></button></div>')
            w(f'<div class="ref">evidence_ref: {_e(item.evidence_ref)}'
              + (' &nbsp;·&nbsp; explanation: LLM-generated prose; verdict, severity, '
                 'ordering and command are deterministic'
                 if item.explanation_source == "llm" else "")
              + '</div>')
            w('</article>')

    # -- all findings ----------------------------------------------------
    w('<h2>All findings</h2><div class="tbl-wrap rv"><table>')
    w('<thead><tr><th>Rule</th><th>Control</th><th>Status</th><th>Severity</th>'
      '<th>Title</th><th>Evidence</th></tr></thead><tbody>')
    for f in report.findings:
        first = (f.evidence.splitlines() or [""])[0]
        if len(first) > 62:
            first = first[:59] + "…"
        key = _STATUS_ICON[f.status]
        w(f'<tr><td class="rid-c">{_e(f.rule_id)}</td><td class="rid-c">{_e(f.control_id)}</td>'
          f'<td><span class="st {key}">{_ICON[key]}{_e(f.status)}</span></td>'
          f'<td style="color:var(--{_SEV_VAR[f.severity]});font-weight:600;font-size:11.5px">'
          f'{_e(f.severity)}</td>'
          f'<td>{_e(f.title)}</td><td class="ev">{_e(first)}</td></tr>')
    w('</tbody></table></div>')

    # -- unknowns --------------------------------------------------------
    unknowns = [f for f in report.findings if f.status == UNKNOWN]
    w('<h2>Unknown verdicts</h2>')
    if not unknowns:
        w('<div class="card rv" style="color:var(--fg-muted)">Every rule reached a '
          'PASS or FAIL verdict on this target.</div>')
    else:
        w('<p style="font-size:13.5px;color:var(--fg-muted);margin:-6px 0 18px">'
          'These checks could not be adjudicated. They are reported with a reason rather '
          'than guessed at, and they do not affect the score.</p>')
        for f in unknowns:
            w('<div class="unk rv"><div class="h">'
              f'<span class="rid">{_e(f.rule_id)}</span>'
              f'<strong style="font-size:14px">{_e(f.title)}</strong></div>'
              f'<div class="r">{_e(f.reason or "no reason recorded")}</div>'
              f'<div class="c">{_e(f.command)}</div></div>')

    # -- command log -----------------------------------------------------
    w('<h2>Command log</h2><details class="rv"><summary>'
      f'{len(report.commands)} read-only commands executed — allowlisted, no shell'
      '</summary><div class="details-body"><div class="tbl-wrap"><table>')
    w('<thead><tr><th>Command</th><th>Exit</th><th>Available</th><th>Feeds</th></tr></thead><tbody>')
    for c in report.commands:
        rules = ", ".join(feeds.get(c.command_id, [])) or "—"
        ok = "var(--accent)" if c.available else "var(--fg-muted)"
        w(f'<tr><td class="rid-c">{_e(c.display)}</td><td class="rid-c">{c.exit_code}</td>'
          f'<td style="color:{ok};font-size:12px">{"yes" if c.available else "no"}</td>'
          f'<td class="ev">{_e(rules)}</td></tr>')
    w('</tbody></table></div></div></details>')

    # -- notes -----------------------------------------------------------
    if report.notes:
        w('<h2>Run notes</h2><div class="card rv"><ul class="notes">')
        for note in report.notes:
            w(f'<li>{_e(note)}</li>')
        w('</ul></div>')

    # -- footer ----------------------------------------------------------
    w('<footer>')
    w(f'<span>SentinelAudit {_e(report.tool_version)} · schema {_e(report.schema_version)} · '
      'read-only, no changes were made to this system</span>')
    w(f'<span class="pill">{_e(report.fingerprint[:16])}…</span>')
    w('</footer>')

    w('</div>')

    # -- behaviour: copy + reveal. No external scripts. -------------------
    w("""<script>
(function(){
  document.querySelectorAll('.copy').forEach(function(b){
    b.addEventListener('click', function(){
      var el = document.getElementById(b.dataset.t);
      var txt = el ? el.textContent : '';
      var done = function(){
        b.classList.add('done');
        var s = b.querySelector('span'); var old = s.textContent; s.textContent = 'Copied';
        setTimeout(function(){ b.classList.remove('done'); s.textContent = old; }, 1600);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(txt).then(done, function(){});
      } else {
        var t = document.createElement('textarea');
        t.value = txt; t.setAttribute('readonly','');
        t.style.cssText = 'position:absolute;left:-9999px';
        document.body.appendChild(t); t.select();
        try { document.execCommand('copy'); done(); } catch(e){}
        document.body.removeChild(t);
      }
    });
  });
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var els = document.querySelectorAll('.rv');
  if (reduce || !('IntersectionObserver' in window)) {
    els.forEach(function(el){ el.classList.add('in'); });
    return;
  }
  var io = new IntersectionObserver(function(entries){
    entries.forEach(function(en){
      if (en.isIntersecting) { en.target.classList.add('in'); io.unobserve(en.target); }
    });
  }, { rootMargin: '0px 0px -8% 0px', threshold: 0.04 });
  els.forEach(function(el){ io.observe(el); });
  // Failsafe: if anything goes wrong with the observer, show all content.
  setTimeout(function(){ els.forEach(function(el){ el.classList.add('in'); }); }, 1200);
})();
</script>""")

    w("</body></html>")
    return "\n".join(out)


def write_html(report: AuditReport, path: str, feeds: dict[str, list[str]]) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_html(report, feeds))
    return path

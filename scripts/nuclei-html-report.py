#!/usr/bin/env python3
"""
Generate a grouped HTML report from Nuclei JSONL or regular text output.

Examples:
  nuclei -t ./templates -l targets.txt -jsonl -o results.jsonl
  python3 scripts/nuclei-html-report.py --input results.jsonl --output report.html

  python3 scripts/nuclei-html-report.py --targets targets.txt --templates ./templates --output report.html
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}

SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "unknown": "Unknown",
}


@dataclass
class TemplateMeta:
    template_id: str
    name: str = ""
    severity: str = "unknown"
    description: str = ""
    tags: list[str] = field(default_factory=list)
    path: str = ""


@dataclass
class Finding:
    template_id: str
    name: str
    severity: str
    description: str
    matched_at: str
    target: str
    template_path: str = ""
    tags: list[str] = field(default_factory=list)
    extractor_values: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    matcher_name: str = ""
    raw_count: int = 0


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def normalize_severity(value: Any) -> str:
    severity = str(value or "unknown").lower()
    return severity if severity in SEVERITY_ORDER else "unknown"


def read_template_metadata(template_root: pathlib.Path) -> dict[str, TemplateMeta]:
    metadata: dict[str, TemplateMeta] = {}
    for path in template_root.rglob("*.yaml"):
        meta = parse_template_file(path)
        if meta and meta.template_id:
            metadata[meta.template_id] = meta
    return metadata


def parse_template_file(path: pathlib.Path) -> TemplateMeta | None:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text) or {}
        info = data.get("info") or {}
        template_id = str(data.get("id") or "")
        return TemplateMeta(
            template_id=template_id,
            name=str(info.get("name") or template_id),
            severity=normalize_severity(info.get("severity")),
            description=clean_description(str(info.get("description") or "")),
            tags=[str(tag) for tag in info.get("tags") or []],
            path=str(path),
        )
    except Exception:
        return parse_template_file_fallback(text, path)


def parse_template_file_fallback(text: str, path: pathlib.Path) -> TemplateMeta | None:
    template_id = ""
    name = ""
    severity = "unknown"
    description_lines: list[str] = []
    tags: list[str] = []
    in_info = False
    in_description = False
    in_tags = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")
        stripped = line.strip()
        if stripped.startswith("id:") and not template_id:
            template_id = stripped.split(":", 1)[1].strip().strip('"\'')
        if stripped == "info:":
            in_info = True
            continue
        if in_info and line and not line.startswith(" ") and not stripped.startswith("-"):
            in_info = False
            in_description = False
            in_tags = False
        if not in_info:
            continue
        if stripped.startswith("name:"):
            name = stripped.split(":", 1)[1].strip().strip('"\'')
            in_description = False
            in_tags = False
        elif stripped.startswith("severity:"):
            severity = normalize_severity(stripped.split(":", 1)[1].strip().strip('"\''))
            in_description = False
            in_tags = False
        elif stripped.startswith("description:"):
            in_description = True
            in_tags = False
            value = stripped.split(":", 1)[1].strip()
            if value and value not in ("|", ">"):
                description_lines.append(value.strip('"\''))
        elif stripped.startswith("tags:"):
            in_tags = True
            in_description = False
        elif in_description:
            if stripped.startswith("- ") or stripped.endswith(":"):
                in_description = False
            elif stripped:
                description_lines.append(stripped)
        elif in_tags and stripped.startswith("- "):
            tags.append(stripped[2:].strip().strip('"\''))

    if not template_id:
        return None
    return TemplateMeta(
        template_id=template_id,
        name=name or template_id,
        severity=severity,
        description=clean_description("\n".join(description_lines)),
        tags=tags,
        path=str(path),
    )


def clean_description(value: str) -> str:
    return " ".join(value.replace("\r", "\n").split())


def read_jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    invalid = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                invalid += 1
                if invalid <= 5:
                    print(f"[WARN] Ignoring invalid JSON at {path}:{line_no}: {exc}", file=sys.stderr)
    if invalid > 5:
        print(f"[WARN] Ignored {invalid} non-JSON lines from {path}", file=sys.stderr)
    return rows


def read_results(path: pathlib.Path, input_format: str) -> list[dict[str, Any]]:
    if input_format == "jsonl":
        return read_jsonl(path)
    if input_format == "text":
        return read_nuclei_text(path)

    first = first_non_empty_line(path)
    if first.startswith("{"):
        rows = read_jsonl(path)
        if rows:
            return rows
    text_rows = read_nuclei_text(path)
    if text_rows:
        print(f"[INFO] Parsed regular Nuclei text output from {path}. For richer reports, generate JSONL with: nuclei -t ./templates -l targets.txt -jsonl -o resultados.jsonl", file=sys.stderr)
        return text_rows
    return read_jsonl(path)


def first_non_empty_line(path: pathlib.Path) -> str:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                return stripped
    return ""


TEXT_RESULT_RE = re.compile(
    r"^\[(?P<template>[^\]]+)\]\s+\[(?P<protocol>[^\]]+)\]\s+\[(?P<severity>[^\]]+)\]\s+(?P<matched>\S+)(?:\s+(?P<evidence>.+))?$"
)


def read_nuclei_text(path: pathlib.Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = TEXT_RESULT_RE.match(line.strip())
            if not match:
                continue
            template_token = match.group("template")
            template_id, extractor_name = split_template_token(template_token)
            row: dict[str, Any] = {
                "template-id": template_id,
                "matcher-name": extractor_name,
                "type": match.group("protocol"),
                "info": {"severity": normalize_severity(match.group("severity"))},
                "matched-at": match.group("matched"),
            }
            evidence = parse_text_evidence(match.group("evidence") or "")
            if evidence:
                row["extractor-name"] = extractor_name or "evidence"
                row["extracted-results"] = evidence
            rows.append(row)
    return rows


def split_template_token(value: str) -> tuple[str, str]:
    if ":" not in value:
        return value, ""
    template_id, extractor_name = value.split(":", 1)
    return template_id, extractor_name


def parse_text_evidence(value: str) -> list[str]:
    value = value.strip()
    if not value:
        return []
    if value.startswith("[") and value.endswith("]"):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(item) for item in parsed]
        except Exception:
            pass
    return [value]


def get_template_id(row: dict[str, Any]) -> str:
    return str(row.get("template-id") or row.get("template_id") or row.get("template") or "unknown")


def get_info(row: dict[str, Any]) -> dict[str, Any]:
    info = row.get("info")
    return info if isinstance(info, dict) else {}


def get_matched_at(row: dict[str, Any]) -> str:
    return str(row.get("matched-at") or row.get("matched") or row.get("url") or row.get("host") or "")


def get_target(row: dict[str, Any]) -> str:
    matched_at = get_matched_at(row)
    parsed = urlparse(matched_at)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    host = str(row.get("host") or row.get("ip") or "unknown-target")
    return host


def extract_values(row: dict[str, Any]) -> tuple[str, list[str]]:
    extractor_name = str(row.get("extractor-name") or row.get("extractor_name") or "evidence")
    values = row.get("extracted-results")
    if values is None:
        values = row.get("extracted_results")
    if values is None:
        values = row.get("extractor")
    if values is None:
        return extractor_name, []
    if not isinstance(values, list):
        values = [values]
    return extractor_name, [str(value) for value in values if str(value)]


def aggregate_findings(rows: list[dict[str, Any]], metadata: dict[str, TemplateMeta]) -> list[Finding]:
    grouped: dict[tuple[str, str, str], Finding] = {}
    for row in rows:
        template_id = get_template_id(row)
        meta = metadata.get(template_id)
        info = get_info(row)
        severity = normalize_severity(info.get("severity") or (meta.severity if meta else "unknown"))
        name = str(info.get("name") or (meta.name if meta else template_id))
        description = clean_description(str(info.get("description") or (meta.description if meta else "")))
        matched_at = get_matched_at(row)
        target = get_target(row)
        key = (target, template_id, matched_at)
        if key not in grouped:
            grouped[key] = Finding(
                template_id=template_id,
                name=name,
                severity=severity,
                description=description,
                matched_at=matched_at,
                target=target,
                template_path=meta.path if meta else str(row.get("template-path") or ""),
                tags=meta.tags if meta else [str(tag) for tag in info.get("tags") or []],
                matcher_name=str(row.get("matcher-name") or row.get("matcher_name") or ""),
            )
        finding = grouped[key]
        finding.raw_count += 1
        extractor_name, values = extract_values(row)
        if values:
            finding.extractor_values[extractor_name].extend(values)

    for finding in grouped.values():
        for key, values in list(finding.extractor_values.items()):
            finding.extractor_values[key] = unique(values)

    return sorted(
        grouped.values(),
        key=lambda item: (
            item.target,
            SEVERITY_ORDER.get(item.severity, 99),
            item.template_id,
            item.matched_at,
        ),
    )


def recommendation_for(finding: Finding) -> str:
    template_id = finding.template_id.lower()
    tags = set(tag.lower() for tag in finding.tags)
    if "missing-security-headers" in template_id or "headers" in tags:
        return "Revisar la politica de cabeceras HTTP y definir HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy y Permissions-Policy segun el contexto de la aplicacion."
    if "swagger" in tags or "openapi" in tags or "knife4j" in tags or "wadl" in tags or "wsdl" in tags:
        return "Restringir documentacion API por entorno, autenticacion o red. Verificar que no expone endpoints internos, modelos sensibles, rutas administrativas u OAuth/client details."
    if "tomcat" in tags or "manager" in tags:
        return "Limitar el acceso por red, revisar roles/credenciales, eliminar artefactos por defecto y validar que Manager/Host Manager no sean accesibles desde redes no confiables."
    if "fingerprint" in tags or finding.severity == "info":
        return "Usar como contexto de triage. Correlacionar tecnologia y version con inventario, exposiciones y CVEs aplicables."
    if "exposure" in tags or "sensitive" in tags:
        return "Retirar el recurso publicado o protegerlo con autenticacion y controles de red. Revisar si el contenido contiene secretos, rutas internas o datos operativos."
    if "admin" in tags or "console" in tags or "management" in tags:
        return "Cerrar exposicion publica, aplicar allowlist/VPN, SSO/MFA cuando aplique y revisar permisos de administracion."
    return "Validar impacto manualmente, confirmar si el recurso debe ser publico y aplicar restriccion por red, autenticacion o configuracion segura."


def path_from_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        return url
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return path


def render_evidence(finding: Finding) -> str:
    parts: list[str] = []
    parts.append(f"<div><strong>URL:</strong> <code>{esc(finding.matched_at)}</code></div>")
    request_path = path_from_url(finding.matched_at)
    if request_path:
        parts.append(f"<div><strong>Ruta:</strong> <code>{esc(request_path)}</code></div>")

    missing_headers = []
    for key, values in finding.extractor_values.items():
        if key == "missing_headers":
            for value in values:
                missing_headers.extend([item.strip() for item in value.split(",") if item.strip()])

    if missing_headers:
        chips = "".join(f"<span class=\"chip warn\">{esc(header)}</span>" for header in unique(missing_headers))
        parts.append(f"<div class=\"evidence-block\"><strong>Cabeceras ausentes:</strong><div class=\"chips\">{chips}</div></div>")

    for key, values in finding.extractor_values.items():
        if key == "missing_headers":
            continue
        title = key.replace("_", " ").replace("-", " ").title()
        rendered_values = "".join(f"<li><code>{esc(value)}</code></li>" for value in values)
        if rendered_values:
            parts.append(f"<div class=\"evidence-block\"><strong>{esc(title)}:</strong><ul>{rendered_values}</ul></div>")

    if finding.raw_count > 1:
        parts.append(f"<div class=\"muted\">Eventos Nuclei agrupados: {finding.raw_count}</div>")
    return "\n".join(parts)


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def severity_badge(severity: str) -> str:
    label = SEVERITY_LABELS.get(severity, severity.title())
    return f"<span class=\"sev sev-{esc(severity)}\">{esc(label)}</span>"


def tag_chips(tags: list[str]) -> str:
    return "".join(f"<span class=\"chip\">{esc(tag)}</span>" for tag in tags[:12])


def render_html(findings: list[Finding], source_file: str) -> str:
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    targets = sorted(set(finding.target for finding in findings))
    severity_counts = Counter(finding.severity for finding in findings)
    total = len(findings)
    actionable = sum(severity_counts[sev] for sev in ("critical", "high", "medium"))

    target_sections = []
    by_target: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_target[finding.target].append(finding)

    for target in targets:
        items = by_target[target]
        counts = Counter(item.severity for item in items)
        cards = "\n".join(render_finding_card(item) for item in items)
        count_badges = " ".join(
            f"<span class=\"mini-count {sev}\">{SEVERITY_LABELS[sev]}: {counts.get(sev, 0)}</span>"
            for sev in ("critical", "high", "medium", "low", "info")
            if counts.get(sev, 0)
        )
        target_sections.append(
            f"""
            <section class="target-section">
              <div class="target-heading">
                <div>
                  <h2>{esc(target)}</h2>
                  <p>{len(items)} findings agrupados</p>
                </div>
                <div class="count-row">{count_badges}</div>
              </div>
              <div class="cards">{cards}</div>
            </section>
            """
        )

    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>scan-nuclei report</title>
  <style>
    :root {{
      --bg: #0b1220;
      --panel: #111827;
      --panel-2: #172033;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --line: #2b3548;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #f59e0b;
      --low: #38bdf8;
      --info: #a78bfa;
      --ok: #22c55e;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: linear-gradient(135deg, #08111f 0%, #102033 55%, #0c2f2c 100%);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    a {{ color: #7dd3fc; }}
    code {{
      background: #0a1020;
      color: #dbeafe;
      border: 1px solid #263247;
      border-radius: 6px;
      padding: 2px 6px;
      word-break: break-all;
    }}
    .page {{ max-width: 1220px; margin: 0 auto; padding: 38px 22px 64px; }}
    .hero {{
      border: 1px solid rgba(226, 232, 240, .14);
      background: rgba(10, 16, 32, .78);
      border-radius: 22px;
      padding: 34px;
      box-shadow: 0 24px 70px rgba(0, 0, 0, .34);
    }}
    .eyebrow {{ color: #93c5fd; font-weight: 700; text-transform: uppercase; letter-spacing: .08em; font-size: 12px; }}
    h1 {{ margin: 8px 0 10px; font-size: clamp(34px, 5vw, 58px); line-height: 1; }}
    .subtitle {{ color: #cbd5e1; max-width: 860px; font-size: 18px; margin: 0; }}
    .stats {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-top: 28px; }}
    .stat {{ background: rgba(17, 24, 39, .85); border: 1px solid var(--line); border-radius: 16px; padding: 18px; }}
    .stat strong {{ display: block; font-size: 34px; line-height: 1; }}
    .stat span {{ color: var(--muted); font-size: 14px; }}
    .toolbar {{ margin: 22px 0; color: var(--muted); display: flex; gap: 12px; flex-wrap: wrap; }}
    .toolbar .pill {{ border: 1px solid var(--line); border-radius: 999px; padding: 7px 12px; background: rgba(17, 24, 39, .72); }}
    .target-section {{ margin-top: 28px; }}
    .target-heading {{
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 18px;
      border-bottom: 1px solid var(--line);
      padding-bottom: 14px;
      margin-bottom: 16px;
    }}
    .target-heading h2 {{ margin: 0; font-size: 24px; }}
    .target-heading p {{ margin: 4px 0 0; color: var(--muted); }}
    .count-row {{ display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }}
    .mini-count {{ border-radius: 999px; padding: 6px 10px; font-size: 12px; font-weight: 800; background: #172033; border: 1px solid var(--line); }}
    .mini-count.critical {{ color: #fecaca; border-color: rgba(239, 68, 68, .45); }}
    .mini-count.high {{ color: #fed7aa; border-color: rgba(249, 115, 22, .45); }}
    .mini-count.medium {{ color: #fde68a; border-color: rgba(245, 158, 11, .45); }}
    .mini-count.low {{ color: #bae6fd; border-color: rgba(56, 189, 248, .45); }}
    .mini-count.info {{ color: #ddd6fe; border-color: rgba(167, 139, 250, .45); }}
    .cards {{ display: grid; gap: 14px; }}
    .card {{
      background: rgba(17, 24, 39, .88);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 18px;
    }}
    .card-head {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }}
    .title-wrap h3 {{ margin: 0; font-size: 19px; }}
    .template-id {{ color: var(--muted); font-size: 13px; margin-top: 3px; }}
    .sev {{ border-radius: 999px; padding: 6px 10px; font-size: 12px; font-weight: 900; text-transform: uppercase; }}
    .sev-critical {{ background: rgba(239,68,68,.16); color: #fecaca; border: 1px solid rgba(239,68,68,.55); }}
    .sev-high {{ background: rgba(249,115,22,.16); color: #fed7aa; border: 1px solid rgba(249,115,22,.55); }}
    .sev-medium {{ background: rgba(245,158,11,.16); color: #fde68a; border: 1px solid rgba(245,158,11,.55); }}
    .sev-low {{ background: rgba(56,189,248,.16); color: #bae6fd; border: 1px solid rgba(56,189,248,.55); }}
    .sev-info {{ background: rgba(167,139,250,.16); color: #ddd6fe; border: 1px solid rgba(167,139,250,.55); }}
    .desc {{ color: #d1d5db; margin: 14px 0; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }}
    .box {{ background: #0a1020; border: 1px solid #263247; border-radius: 12px; padding: 14px; }}
    .box h4 {{ margin: 0 0 8px; font-size: 13px; color: #93c5fd; text-transform: uppercase; letter-spacing: .06em; }}
    .box ul {{ margin: 8px 0 0; padding-left: 18px; }}
    .evidence-block {{ margin-top: 10px; }}
    .chips {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }}
    .chip {{ display: inline-flex; border: 1px solid #334155; border-radius: 999px; padding: 4px 8px; color: #cbd5e1; background: #111827; font-size: 12px; margin: 3px 4px 0 0; }}
    .chip.warn {{ color: #fde68a; border-color: rgba(245, 158, 11, .42); background: rgba(245, 158, 11, .08); }}
    .muted {{ color: var(--muted); font-size: 13px; margin-top: 8px; }}
    .footer {{ color: var(--muted); margin-top: 34px; text-align: center; font-size: 13px; }}
    @media (max-width: 780px) {{
      .stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .grid {{ grid-template-columns: 1fr; }}
      .target-heading, .card-head {{ display: block; }}
      .count-row {{ justify-content: flex-start; margin-top: 10px; }}
    }}
  </style>
</head>
<body>
  <main class="page">
    <section class="hero">
      <div class="eyebrow">scan-nuclei report</div>
      <h1>Informe de hallazgos</h1>
      <p class="subtitle">Resultados agrupados por target, severidad y plantilla. Cada finding incluye explicacion, evidencia observable, rutas afectadas y una recomendacion practica.</p>
      <div class="stats">
        <div class="stat"><strong>{total}</strong><span>findings agrupados</span></div>
        <div class="stat"><strong>{len(targets)}</strong><span>targets con resultados</span></div>
        <div class="stat"><strong>{actionable}</strong><span>critical/high/medium</span></div>
        <div class="stat"><strong>{severity_counts.get("info", 0)}</strong><span>fingerprints/contexto</span></div>
      </div>
    </section>
    <div class="toolbar">
      <span class="pill">Generado: {esc(now)}</span>
      <span class="pill">Fuente: {esc(source_file)}</span>
      <span class="pill">Orden: target > severidad > plantilla</span>
    </div>
    {''.join(target_sections)}
    <div class="footer">Generado con scripts/nuclei-html-report.py</div>
  </main>
</body>
</html>
"""


def render_finding_card(finding: Finding) -> str:
    description = finding.description or "La plantilla no incluye descripcion ampliada. Revisar la evidencia y el fichero de plantilla para validar el impacto."
    tags = tag_chips(finding.tags)
    template_path = finding.template_path
    template_line = f"<div class=\"muted\">Template: <code>{esc(template_path)}</code></div>" if template_path else ""
    return f"""
    <article class="card sev-border-{esc(finding.severity)}">
      <div class="card-head">
        <div class="title-wrap">
          <h3>{esc(finding.name)}</h3>
          <div class="template-id">{esc(finding.template_id)}</div>
        </div>
        {severity_badge(finding.severity)}
      </div>
      <p class="desc">{esc(description)}</p>
      <div class="chips">{tags}</div>
      <div class="grid">
        <div class="box">
          <h4>Evidencia</h4>
          {render_evidence(finding)}
        </div>
        <div class="box">
          <h4>Recomendacion</h4>
          <p>{esc(recommendation_for(finding))}</p>
          {template_line}
        </div>
      </div>
    </article>
    """


def run_nuclei(args: argparse.Namespace, output_jsonl: pathlib.Path) -> None:
    command = [
        "nuclei",
        "-t",
        args.templates,
        "-jsonl",
        "-o",
        str(output_jsonl),
    ]
    if args.targets:
        command.extend(["-l", args.targets])
    if args.url:
        command.extend(["-u", args.url])
    if args.severity:
        command.extend(["-severity", args.severity])
    if args.extra_nuclei_args:
        command.extend(args.extra_nuclei_args)

    print("[INFO] Running:", " ".join(shell_quote(part) for part in command))
    if args.show_nuclei_output:
        subprocess.run(command, check=True)
    else:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate a grouped HTML report from Nuclei JSONL or regular text output.")
    parser.add_argument("--input", help="Existing Nuclei JSONL file, or regular Nuclei text output.")
    parser.add_argument("--input-format", choices=["auto", "jsonl", "text"], default="auto", help="Input parser. Default: auto.")
    parser.add_argument("--output", default="nuclei-report.html", help="HTML report path.")
    parser.add_argument("--templates", default="./templates", help="Template directory used to enrich findings.")
    parser.add_argument("--targets", help="Run Nuclei against a target list and generate the report.")
    parser.add_argument("--url", help="Run Nuclei against a single URL and generate the report.")
    parser.add_argument("--severity", help="Optional severity filter passed to Nuclei, for example critical,high,medium.")
    parser.add_argument("--keep-jsonl", help="When running Nuclei, keep raw JSONL at this path.")
    parser.add_argument("--show-nuclei-output", action="store_true", help="Show Nuclei stdout when the script launches a scan.")
    parser.add_argument("extra_nuclei_args", nargs=argparse.REMAINDER, help="Extra args passed to Nuclei after --.")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.extra_nuclei_args and args.extra_nuclei_args[0] == "--":
        args.extra_nuclei_args = args.extra_nuclei_args[1:]

    if not args.input and not args.targets and not args.url:
        parser.error("Provide --input results.jsonl or use --targets/--url to run Nuclei.")

    template_root = pathlib.Path(args.templates)
    metadata = read_template_metadata(template_root)
    output_path = pathlib.Path(args.output)

    if args.input:
        jsonl_path = pathlib.Path(args.input)
        source_label = str(jsonl_path)
    else:
        if args.keep_jsonl:
            jsonl_path = pathlib.Path(args.keep_jsonl)
            jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            run_nuclei(args, jsonl_path)
        else:
            fd, temp_name = tempfile.mkstemp(prefix="nuclei-results-", suffix=".jsonl")
            os.close(fd)
            jsonl_path = pathlib.Path(temp_name)
            run_nuclei(args, jsonl_path)
        source_label = str(jsonl_path)

    rows = read_results(jsonl_path, args.input_format)
    findings = aggregate_findings(rows, metadata)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_html(findings, source_label), encoding="utf-8")
    print(f"[OK] HTML report written to {output_path}")
    print(f"[OK] Grouped findings: {len(findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

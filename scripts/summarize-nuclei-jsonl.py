#!/usr/bin/env python3

import argparse
import json
import sys
from collections import defaultdict
from urllib.parse import urlsplit


def normalize_path(value: str, host_base_path: str = "") -> str:
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        if parsed.scheme and parsed.netloc:
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            if host_base_path and path.startswith(host_base_path.rstrip("/") + "/"):
                path = path[len(host_base_path.rstrip("/")) :]
            elif host_base_path and path == host_base_path:
                path = "/"
            return path
    except Exception:
        pass
    return value


def get_paths(result: dict, host_base_path: str = "") -> list[str]:
    paths = []
    extracted = result.get("extracted-results")
    if isinstance(extracted, list):
        for item in extracted:
            if isinstance(item, str) and item.strip():
                paths.append(normalize_path(item.strip(), host_base_path))
    matched = result.get("matched-at")
    if isinstance(matched, str) and matched.strip():
        m = normalize_path(matched.strip(), host_base_path)
        if m and m not in paths:
            paths.append(m)
    return paths


def parse_jsonl(path: str):
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"JSONL invalido en linea {line_no}: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Agrupa salida JSONL de Nuclei por host+template."
    )
    parser.add_argument(
        "-i", "--input", required=True, help="Ruta al archivo JSONL de Nuclei."
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Formato de salida (default: text).",
    )
    parser.add_argument(
        "--max-paths",
        type=int,
        default=12,
        help="Maximo de paths mostrados por grupo en salida text (default: 12).",
    )
    args = parser.parse_args()

    groups = defaultdict(
        lambda: {
            "template_id": "",
            "template_name": "",
            "type": "",
            "severity": "",
            "host": "",
            "matcher_names": set(),
            "paths": set(),
            "raw_count": 0,
        }
    )

    for result in parse_jsonl(args.input):
        info = result.get("info", {})
        template_id = result.get("template-id", "") or ""
        host = result.get("host", "") or ""
        rtype = result.get("type", "") or ""
        severity = str(info.get("severity", "") or "")
        host_base_path = ""
        try:
            parsed_host = urlsplit(host)
            host_base_path = parsed_host.path or ""
        except Exception:
            host_base_path = ""

        key = (host, template_id, rtype, severity)

        g = groups[key]
        g["template_id"] = template_id
        g["template_name"] = info.get("name", "") or ""
        g["type"] = rtype
        g["severity"] = severity
        g["host"] = host
        g["raw_count"] += 1

        matcher_name = result.get("matcher-name")
        if isinstance(matcher_name, str) and matcher_name.strip():
            g["matcher_names"].add(matcher_name.strip())

        for p in get_paths(result, host_base_path):
            if p:
                g["paths"].add(p)

    rows = []
    for _, g in groups.items():
        rows.append(
            {
                "template_id": g["template_id"],
                "template_name": g["template_name"],
                "type": g["type"],
                "severity": g["severity"],
                "host": g["host"],
                "matchers": sorted(g["matcher_names"]),
                "paths": sorted(g["paths"]),
                "raw_matches": g["raw_count"],
            }
        )

    rows.sort(key=lambda x: (x["host"], x["severity"], x["template_id"]))

    if args.format == "json":
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0

    print(f"[INF] Grupos agregados: {len(rows)}")
    for r in rows:
        sev = r["severity"] or "unknown"
        header = f"[{r['template_id']}] [{r['type']}] [{sev}] {r['host']}"
        if r["matchers"]:
            header += f" [matchers: {','.join(r['matchers'])}]"
        print(header)

        paths = r["paths"]
        if not paths:
            print("  - paths: (sin extractor, usando matched-at no disponible)")
            continue
        shown = paths[: args.max_paths]
        print(f"  - paths ({len(paths)}): " + ", ".join(shown))
        if len(paths) > len(shown):
            print(f"  - ... +{len(paths) - len(shown)} paths adicionales")
        if r["raw_matches"] > len(paths):
            print(f"  - raw_matches: {r['raw_matches']}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as err:
        print(f"[ERR] {err}", file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3

import json
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict
from urllib.parse import urlsplit


ROOT_DIR = Path(__file__).resolve().parent.parent
FIXTURES_PATH = ROOT_DIR / "tests" / "fixtures" / "http-regression-fixtures.json"


@dataclass(frozen=True)
class Case:
    name: str
    family: str
    scenario: str
    scan_mode: str
    target: str
    expected: set[str]
    unexpected: set[str]


CASES = [
    Case(
        name="quarkus-fingerprint-positive",
        family="quarkus",
        scenario="quarkus-positive",
        scan_mode="template",
        target="templates/technologies/quarkus/quarkus-stack-fingerprint.yaml",
        expected={"quarkus-stack-fingerprint"},
        unexpected=set(),
    ),
    Case(
        name="quarkus-fingerprint-negative-generic-health",
        family="quarkus",
        scenario="quarkus-generic-health",
        scan_mode="template",
        target="templates/technologies/quarkus/quarkus-stack-fingerprint.yaml",
        expected=set(),
        unexpected={"quarkus-stack-fingerprint"},
    ),
    Case(
        name="quarkus-workflow-positive",
        family="quarkus",
        scenario="quarkus-positive",
        scan_mode="workflow",
        target="templates/workflows/java/java-modern-stacks-snapshot-workflow.yaml",
        expected={
            "quarkus-dev-ui-surface-exposed",
            "quarkus-openapi-surface-exposed",
            "quarkus-metrics-endpoint-exposed",
        },
        unexpected={"micronaut-signal-fingerprint"},
    ),
    Case(
        name="micronaut-fingerprint-positive",
        family="micronaut",
        scenario="micronaut-positive",
        scan_mode="template",
        target="templates/technologies/micronaut/micronaut-signal-fingerprint.yaml",
        expected={"micronaut-signal-fingerprint"},
        unexpected=set(),
    ),
    Case(
        name="micronaut-fingerprint-negative-hidden-server",
        family="micronaut",
        scenario="micronaut-hidden-server",
        scan_mode="template",
        target="templates/technologies/micronaut/micronaut-signal-fingerprint.yaml",
        expected=set(),
        unexpected={"micronaut-signal-fingerprint"},
    ),
    Case(
        name="micronaut-workflow-positive",
        family="micronaut",
        scenario="micronaut-positive",
        scan_mode="workflow",
        target="templates/workflows/java/java-modern-stacks-snapshot-workflow.yaml",
        expected={
            "micronaut-env-endpoint-exposed",
            "micronaut-management-endpoints-exposed",
            "micronaut-loggers-write-surface-exposed",
            "micronaut-refresh-write-surface-exposed",
        },
        unexpected={"quarkus-stack-fingerprint"},
    ),
    Case(
        name="apache-server-status-positive",
        family="apache",
        scenario="apache-positive",
        scan_mode="template",
        target="templates/misconfiguration/apache/apache-server-status-exposed.yaml",
        expected={"apache-server-status-exposed"},
        unexpected=set(),
    ),
    Case(
        name="apache-server-status-negative-hidden-server",
        family="apache",
        scenario="apache-hidden-server",
        scan_mode="template",
        target="templates/misconfiguration/apache/apache-server-status-exposed.yaml",
        expected=set(),
        unexpected={"apache-server-status-exposed"},
    ),
    Case(
        name="apache-proxy-backend-routing-positive",
        family="apache",
        scenario="apache-proxy-positive",
        scan_mode="template",
        target="templates/misconfiguration/apache/apache-proxy-backend-routing-disclosure-exposed.yaml",
        expected={"apache-proxy-backend-routing-disclosure-exposed"},
        unexpected=set(),
    ),
    Case(
        name="apache-proxy-wstunnel-routing-positive",
        family="apache",
        scenario="apache-proxy-positive",
        scan_mode="template",
        target="templates/misconfiguration/apache/apache-proxy-wstunnel-routing-signal-exposed.yaml",
        expected={"apache-proxy-wstunnel-routing-signal-exposed"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-fingerprint-positive",
        family="tomcat",
        scenario="tomcat-positive",
        scan_mode="template",
        target="templates/technologies/tomcat/tomcat-version-hint-fingerprint.yaml",
        expected={"tomcat-version-hint-fingerprint"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-fingerprint-negative-generic",
        family="tomcat",
        scenario="tomcat-generic",
        scan_mode="template",
        target="templates/technologies/tomcat/tomcat-version-hint-fingerprint.yaml",
        expected=set(),
        unexpected={"tomcat-version-hint-fingerprint"},
    ),
    Case(
        name="tomcat-manager-positive",
        family="tomcat",
        scenario="tomcat-positive",
        scan_mode="template",
        target="templates/misconfiguration/tomcat/tomcat-manager-html-exposed.yaml",
        expected={"tomcat-manager-html-exposed"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-server-xml-positive",
        family="tomcat",
        scenario="tomcat-positive",
        scan_mode="template",
        target="templates/exposures/sensitive-paths/tomcat-server-xml-exposed.yaml",
        expected={"tomcat-server-xml-exposed"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-global-naming-resources-positive",
        family="tomcat",
        scenario="tomcat-positive",
        scan_mode="template",
        target="templates/exposures/sensitive-paths/tomcat-global-naming-resources-exposed.yaml",
        expected={"tomcat-global-naming-resources-exposed"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-users-xml-positive",
        family="tomcat",
        scenario="tomcat-positive",
        scan_mode="template",
        target="templates/exposures/sensitive-paths/tomcat-users-xml-exposed.yaml",
        expected={"tomcat-users-xml-exposed"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-web-xml-positive",
        family="tomcat",
        scenario="tomcat-positive",
        scan_mode="template",
        target="templates/exposures/sensitive-paths/tomcat-web-xml-exposed.yaml",
        expected={"tomcat-web-xml-exposed"},
        unexpected=set(),
    ),
    Case(
        name="web-inf-web-xml-positive",
        family="tomcat",
        scenario="tomcat-positive",
        scan_mode="template",
        target="templates/exposures/sensitive-paths/web-inf-web-xml-exposed.yaml",
        expected={"web-inf-web-xml-exposed"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-app-context-temp-variant-positive",
        family="tomcat",
        scenario="tomcat-positive",
        scan_mode="template",
        target="templates/exposures/sensitive-paths/tomcat-catalina-localhost-app-xml-temp-variants-exposed.yaml",
        expected={"tomcat-catalina-localhost-app-xml-temp-variants-exposed"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-catalina-localhost-xml-variant-positive",
        family="tomcat",
        scenario="tomcat-positive",
        scan_mode="template",
        target="templates/exposures/sensitive-paths/tomcat-catalina-localhost-xml-variants-exposed.yaml",
        expected={"tomcat-catalina-localhost-xml-variants-exposed"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-jndi-resource-app-positive",
        family="tomcat",
        scenario="tomcat-positive",
        scan_mode="template",
        target="templates/exposures/sensitive-paths/tomcat-jndi-resources-exposed.yaml",
        expected={"tomcat-jndi-resources-exposed"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-context-xml-positive",
        family="tomcat",
        scenario="tomcat-positive",
        scan_mode="template",
        target="templates/exposures/sensitive-paths/tomcat-context-xml-exposed.yaml",
        expected={"tomcat-context-xml-exposed"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-context-resource-backup-app-positive",
        family="tomcat",
        scenario="tomcat-positive",
        scan_mode="template",
        target="templates/exposures/sensitive-paths/tomcat-context-resource-backups-exposed.yaml",
        expected={"tomcat-context-resource-backups-exposed"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-app-context-expanded-name-positive",
        family="tomcat",
        scenario="tomcat-expanded-positive",
        scan_mode="template",
        target="templates/exposures/sensitive-paths/tomcat-catalina-localhost-app-xml-temp-variants-exposed.yaml",
        expected={"tomcat-catalina-localhost-app-xml-temp-variants-exposed"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-jndi-expanded-name-positive",
        family="tomcat",
        scenario="tomcat-expanded-positive",
        scan_mode="template",
        target="templates/exposures/sensitive-paths/tomcat-jndi-resources-exposed.yaml",
        expected={"tomcat-jndi-resources-exposed"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-context-resource-backup-expanded-name-positive",
        family="tomcat",
        scenario="tomcat-expanded-positive",
        scan_mode="template",
        target="templates/exposures/sensitive-paths/tomcat-context-resource-backups-exposed.yaml",
        expected={"tomcat-context-resource-backups-exposed"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-app-archive-temp-artifact-positive",
        family="tomcat",
        scenario="tomcat-positive",
        scan_mode="template",
        target="templates/exposures/sensitive-paths/tomcat-app-archive-temp-artifacts-exposed.yaml",
        expected={"tomcat-app-archive-temp-artifacts-exposed"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-app-archive-expanded-name-positive",
        family="tomcat",
        scenario="tomcat-expanded-positive",
        scan_mode="template",
        target="templates/exposures/sensitive-paths/tomcat-app-archive-temp-artifacts-exposed.yaml",
        expected={"tomcat-app-archive-temp-artifacts-exposed"},
        unexpected=set(),
    ),
    Case(
        name="tomcat-workflow-positive",
        family="tomcat",
        scenario="tomcat-positive",
        scan_mode="workflow",
        target="templates/workflows/tomcat/tomcat-version-priority-workflow.yaml",
        expected={
            "tomcat-app-archive-temp-artifacts-exposed",
            "tomcat-catalina-localhost-xml-variants-exposed",
            "tomcat-context-xml-exposed",
            "tomcat-global-naming-resources-exposed",
            "tomcat-manager-html-exposed",
            "tomcat-catalina-localhost-app-xml-temp-variants-exposed",
            "tomcat-jndi-resources-exposed",
            "tomcat-server-xml-exposed",
            "tomcat-context-resource-backups-exposed",
            "tomcat-users-xml-exposed",
            "tomcat-web-xml-exposed",
            "web-inf-web-xml-exposed",
        },
        unexpected=set(),
    ),
    Case(
        name="wildfly-fingerprint-positive",
        family="wildfly",
        scenario="wildfly-positive",
        scan_mode="template",
        target="templates/technologies/wildfly/wildfly-server-header-fingerprint.yaml",
        expected={"wildfly-server-header-fingerprint"},
        unexpected=set(),
    ),
    Case(
        name="wildfly-fingerprint-negative-generic",
        family="wildfly",
        scenario="wildfly-generic",
        scan_mode="template",
        target="templates/technologies/wildfly/wildfly-server-header-fingerprint.yaml",
        expected=set(),
        unexpected={"wildfly-server-header-fingerprint"},
    ),
    Case(
        name="wildfly-health-positive",
        family="wildfly",
        scenario="wildfly-positive",
        scan_mode="template",
        target="templates/misconfiguration/wildfly/wildfly-health-endpoints-exposed.yaml",
        expected={"wildfly-health-endpoints-exposed"},
        unexpected=set(),
    ),
    Case(
        name="wildfly-domain-topology-positive",
        family="wildfly",
        scenario="wildfly-positive",
        scan_mode="template",
        target="templates/misconfiguration/wildfly/wildfly-domain-topology-management-unauth.yaml",
        expected={"wildfly-domain-topology-management-unauth"},
        unexpected=set(),
    ),
    Case(
        name="wildfly-domain-deployment-details-positive",
        family="wildfly",
        scenario="wildfly-positive",
        scan_mode="template",
        target="templates/misconfiguration/wildfly/wildfly-domain-deployment-details-management-unauth.yaml",
        expected={"wildfly-domain-deployment-details-management-unauth"},
        unexpected=set(),
    ),
    Case(
        name="wildfly-workflow-positive",
        family="wildfly",
        scenario="wildfly-positive",
        scan_mode="workflow",
        target="templates/workflows/wildfly/wildfly-modern-admin-surface-workflow.yaml",
        expected={
            "wildfly-health-endpoints-exposed",
            "wildfly-domain-topology-management-unauth",
            "wildfly-domain-deployment-details-management-unauth",
        },
        unexpected=set(),
    ),
    Case(
        name="spring-fingerprint-positive",
        family="spring",
        scenario="spring-positive",
        scan_mode="template",
        target="templates/technologies/spring-boot/spring-boot-whitelabel-fingerprint.yaml",
        expected={"spring-boot-whitelabel-fingerprint"},
        unexpected=set(),
    ),
    Case(
        name="spring-fingerprint-negative-generic",
        family="spring",
        scenario="spring-generic",
        scan_mode="template",
        target="templates/technologies/spring-boot/spring-boot-whitelabel-fingerprint.yaml",
        expected=set(),
        unexpected={"spring-boot-whitelabel-fingerprint"},
    ),
    Case(
        name="spring-actuator-prometheus-positive",
        family="spring",
        scenario="spring-positive",
        scan_mode="template",
        target="templates/misconfiguration/java-apps/spring-actuator-prometheus-exposed.yaml",
        expected={"spring-actuator-prometheus-exposed"},
        unexpected=set(),
    ),
    Case(
        name="spring-workflow-positive",
        family="spring",
        scenario="spring-positive",
        scan_mode="workflow",
        target="templates/workflows/spring/spring-fingerprint-to-risk-workflow.yaml",
        expected={
            "spring-actuator-prometheus-exposed",
        },
        unexpected=set(),
    ),
]


with FIXTURES_PATH.open("r", encoding="utf-8") as handle:
    FIXTURES: Dict[str, Dict[str, dict]] = json.load(handle)


def scenario_base_url(port: int, scenario: str) -> str:
    return f"http://127.0.0.1:{port}/{scenario}"


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "scan-nuclei-fixtures/1.0"
    fixtures = FIXTURES

    def log_message(self, format: str, *args) -> None:
        return

    # Keep headers deterministic for templates that anchor on the beginning of
    # the header block (for example "^server: ...").
    def send_response(self, code: int, message: str | None = None) -> None:
        self.log_request(code)
        self.send_response_only(code, message)

    def do_GET(self) -> None:
        self._respond("GET")

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length:
            self.rfile.read(content_length)
        self._respond("POST")

    def _respond(self, method: str) -> None:
        parsed = urlsplit(self.path)
        segments = [segment for segment in parsed.path.split("/") if segment]
        if not segments:
            self.send_error(404)
            return

        scenario = segments[0]
        scenario_routes = self.fixtures.get(scenario)
        if scenario_routes is None:
            self.send_error(404)
            return

        path = "/" + "/".join(segments[1:])
        if not path or path == "/":
            path = "/"

        key = f"{method} {path}"
        if parsed.query:
            key_with_query = f"{key}?{parsed.query}"
            route = scenario_routes.get(key_with_query)
        else:
            route = None

        if route is None:
            route = scenario_routes.get(key)

        if route is None:
            self.send_error(404)
            return

        body = route.get("body", "").encode("utf-8")
        self.send_response(route.get("status", 200))
        for header_name, header_value in route.get("headers", {}).items():
            self.send_header(header_name, header_value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_case(port: int, case: Case) -> tuple[bool, str]:
    base_url = scenario_base_url(port, case.scenario)

    with tempfile.NamedTemporaryFile(prefix="nuclei-regression-", suffix=".jsonl") as output_file:
        cmd = [
            "nuclei",
            "-duc",
            "-ni",
            "-nc",
            "-or",
            "-jsonl",
            "-o",
            output_file.name,
            "-u",
            base_url,
        ]
        if case.scan_mode == "template":
            cmd.extend(["-t", case.target])
        else:
            cmd.extend(["-w", case.target])

        proc = subprocess.run(
            cmd,
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            return False, f"{case.name}: nuclei devolvio {proc.returncode}\n{proc.stderr or proc.stdout}"

        found = set()
        content = Path(output_file.name).read_text(encoding="utf-8").strip()
        if content:
            for line in content.splitlines():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    return False, f"{case.name}: JSONL invalido: {exc}"
                template_id = item.get("template-id")
                if isinstance(template_id, str) and template_id:
                    found.add(template_id)

        missing = sorted(case.expected - found)
        unexpected = sorted(case.unexpected & found)
        if missing or unexpected:
            details = [f"{case.name}: base_url={base_url}"]
            if missing:
                details.append(f"faltan matches esperados: {', '.join(missing)}")
            if unexpected:
                details.append(f"aparecen matches no esperados: {', '.join(unexpected)}")
            details.append(f"matches observados: {', '.join(sorted(found)) or '(ninguno)'}")
            return False, "\n".join(details)

        return True, f"[OK] {case.name}: {', '.join(sorted(found)) or '(sin matches esperados y sin matches)'}"


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    print(f"[INF] Fixtures HTTP locales en http://127.0.0.1:{server.server_port}")

    failures = []
    family_totals: dict[str, int] = {}
    family_failures: dict[str, int] = {}
    try:
        for case in CASES:
            family_totals[case.family] = family_totals.get(case.family, 0) + 1
            ok, message = run_case(server.server_port, case)
            print(message)
            if not ok:
                failures.append(case.name)
                family_failures[case.family] = family_failures.get(case.family, 0) + 1
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    print("[INF] Resumen por familia:")
    for family in sorted(family_totals):
        total = family_totals[family]
        failed = family_failures.get(family, 0)
        passed = total - failed
        print(f"[INF] {family}: {passed}/{total} casos OK")

    if failures:
        print(f"[ERR] Casos fallidos: {', '.join(failures)}", file=sys.stderr)
        return 1

    print(f"[OK] Regresion HTTP completada: {len(CASES)} casos")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

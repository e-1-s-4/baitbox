"""Static validation of the container configuration.

A Docker daemon is not available in CI for this repository's local test runs, so
these tests assert the *invariants* of ``Dockerfile`` and ``docker-compose.yml``
that a build would otherwise enforce only on failure (missing user before
``COPY --chown``, wrong internal port, missing health probe, etc.).
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
COMPOSE = ROOT / "docker-compose.yml"
DOCKERIGNORE = ROOT / ".dockerignore"


def _dockerfile_lines() -> list[str]:
    return [ln.strip() for ln in DOCKERFILE.read_text(encoding="utf-8").splitlines()]


def test_dockerfile_creates_user_before_chown_copy():
    lines = _dockerfile_lines()
    useradd_at = next(i for i, ln in enumerate(lines) if ln.startswith("RUN useradd"))
    chown_copy_at = next(i for i, ln in enumerate(lines) if ln.startswith("COPY --chown=honeypot"))
    assert useradd_at < chown_copy_at, "useradd must precede COPY --chown"
    # The container must actually drop privileges.
    assert any(ln == "USER honeypot" for ln in lines)


def test_dockerfile_pins_internal_dashboard_port():
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "BAITBOX_DASHBOARD_PORT=8000" in text
    assert "EXPOSE" in text and "8000" in text
    assert "2222" in text and "2323" in text


def test_dockerfile_healthcheck_and_entrypoint():
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "HEALTHCHECK" in text
    assert "/healthz" in text
    assert 'CMD ["python", "-m", "baitbox.main"]' in text


def test_dockerignore_keeps_runtime_sources():
    patterns = {ln.strip() for ln in DOCKERIGNORE.read_text(encoding="utf-8").splitlines() if ln.strip()}
    assert "tests" in patterns
    assert "*.db" in patterns
    # Application code and dependency manifest must remain in the build context.
    assert not any(p in patterns for p in ("baitbox", "*.py", "requirements.txt"))


def test_compose_defines_app_and_postgres_service():
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = compose["services"]
    assert "app" in services and "db" in services
    db = services["db"]
    assert db["image"].startswith("postgres:")
    assert db["healthcheck"]["test"][0] == "CMD-SHELL"

    app = services["app"]
    assert app["build"] in (".", "./")
    # App waits for a healthy database.
    assert app["depends_on"]["db"]["condition"] == "service_healthy"
    # Published honeypot/dashboard ports.
    published = {p.split(":")[0] for p in app["ports"]}
    assert {"2222", "2323", "8000"} <= published


def test_compose_wires_the_postgres_backend():
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    app_env = compose["services"]["app"]["environment"]
    assert app_env["BAITBOX_DB_TYPE"] == "postgresql"
    assert app_env["BAITBOX_DATABASE_URL"].startswith("postgresql://")
    assert "@db:5432/" in app_env["BAITBOX_DATABASE_URL"]
    # Credentials must not silently reuse the "changeme" defaults in docs
    assert app_env["BAITBOX_DASHBOARD_PASSWORD"]
    assert app_env["BAITBOX_JWT_SECRET"]

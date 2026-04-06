# Legacy Cleanup Report

## 1. Was wurde entfernt

Folgende Legacy-Bereiche wurden aus dem Repository entfernt:

### Alter Python-/`rootbot`-Stack

- gesamtes `root_bot/`
- alte Python-Einstiege und Tests:
  - `rootbot-cli.py`
  - `watchdog.py`
  - `test_bot.py`
  - `run_bot.sh`
  - `stop_bot.sh`
  - `setup.py`
  - `requirements.txt`
  - `requirements-dev.txt`
  - `bin/rootbot`
  - `bin/rootbot-cli`
  - `bin/rootbot-monitor`
  - `bin/rootbot-docker`

### Legacy-Deployment und konkurrierende Betriebsmodelle

- `rootbot.service`
- `rootbot.apparmor`
- `rootbot.conf`
- `install.sh`
- `setup_security.sh`
- `setup_permissions.sh`
- `Dockerfile`
- `Dockerfile.test`
- `docker-compose.yml`
- `prometheus.yml`
- `elk/`
- `.dockerignore`

### Veraltete Dokumentation und Altplanung

- `docs/examples/rootbot.conf`
- `docs/troubleshooting.md`
- `RoadMap.md`
- `IMPLEMENTATION_PLAN.md`
- `Pitch.md`

### Duplizierter Altbestand

- komplettes Unterverzeichnis `Smolit_AdminBot/`

## 2. Was wurde bewusst behalten

- kompletter Rust-Produktivpfad:
  - `src/`
  - `adminbotd.service`
  - `config/policy.example.toml`
  - `deploy/polkit/*`
  - `scripts/verify_security_release_gate.sh`
  - `src/bin/adminbotctl.rs`
  - `src/cli/*`
- Architektur- und Sicherheitsdokumentation:
  - `docs/adminbot_v2/*`
  - `docs/security/*`
  - `docs/cli/adminbotctl.md`
- aktuelle v2-IPC-Testhilfen:
  - `scripts/send_request.sh`
  - `scripts/test_success_case.sh`
  - `scripts/test_policy_deny_case.sh`

## 3. Welche REVIEW-Faelle offen geblieben sind

- `scripts/send_request.sh` nutzt weiterhin ein kleines `python3`-Inline-Snippet zum Framing von Raw-IPC-Requests.
  - bewusst behalten, weil es das aktuelle v2-Protokoll testet und in der README referenziert ist
  - falls ein spaeterer Zero-Python-Tooling-Stand gewuenscht ist, sollte dieser Ersatz separat und bewusst erfolgen
- untracked lokale Doku unter `docs/security/` und `docs/releases/`
  - nicht Teil dieses Cleanup-Commits
  - kein Legacy-Bestand, daher bewusst nicht mitbereinigt
- `DevPrompt.md`
  - lokal vorhanden, aber nicht getrackt und nicht Teil des Produkt-Scopes

## 4. Welche Referenzen/Doku angepasst wurden

- `README.md`
  - klar auf das Rust-/AdminBot-v2-Zielbild fokussiert
  - Legacy-Python-/`rootbot`-Modell nicht mehr als Repo-Bestand dargestellt
- `docs/cleanup/LEGACY_CLEANUP_PLAN.md`
  - Inventur und Entscheidungsbasis vor dem Cleanup

## 5. Repo ist jetzt auf Rust-/AdminBot-v2-Zielbild reduziert: ja/nein

Ja, fuer den getrackten Produktbestand.

Das Repository bildet jetzt im Wesentlichen nur noch folgende kanonische Bereiche ab:

- Rust-Daemon und CLI
- v2-Architektur- und Sicherheitsdokumentation
- Policy-/polkit-/systemd-Artefakte
- Security Release Gate

Offen bleiben nur bewusst nicht angefasste lokale/untracked Dokumente sowie die kleinen aktuellen IPC-Testhilfen.

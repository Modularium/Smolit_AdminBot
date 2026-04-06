# Legacy Cleanup Plan

## 1. Ziel des Cleanup

Das Repository soll auf das aktuelle AdminBot-v2-Zielbild reduziert werden:

- Rust-basierter `adminbotd`
- gehärtete systemd-/polkit-/Policy-Artefakte
- `adminbotctl`
- `docs/adminbot_v2/*`
- `docs/security/*`
- Security Release Gate

Entfernt werden nur Artefakte, die nachweislich zum alten Python-/`rootbot`-Modell gehoeren oder ein veraltetes alternatives Betriebsmodell dokumentieren.

## 2. Sicher KEEP

Diese Bereiche sind kanonisch fuer das aktuelle Zielbild und werden nicht angetastet:

- `src/`
- `Cargo.toml`
- `Cargo.lock`
- `adminbotd.service`
- `config/policy.example.toml`
- `deploy/polkit/*`
- `scripts/verify_security_release_gate.sh`
- `src/bin/adminbotctl.rs`
- `src/cli/*`
- `docs/adminbot_v2/*`
- `docs/security/*`
- `docs/cli/adminbotctl.md`
- `.github/workflows/security-gate.yml`
- `README.md`
- `AGENTS.md`

Zusatz:

- `scripts/send_request.sh`
- `scripts/test_success_case.sh`
- `scripts/test_policy_deny_case.sh`

Diese drei Skripte bleiben bewusst erhalten. Sie sind keine Alt-Implementierung, sondern aktuelle v2-IPC-Helfer fuer Low-Level-Tests und werden in der README noch referenziert.

## 3. Sicher REMOVE

Diese Bereiche sind eindeutig Legacy und nicht mehr Teil des Rust-/Security-/CLI-Zielbilds:

### Python- und `rootbot`-Runtime

- `root_bot/`
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

### Veraltete Dokumentation zum Altmodell

- `docs/examples/rootbot.conf`
- `docs/troubleshooting.md`
- `RoadMap.md`
- `IMPLEMENTATION_PLAN.md`
- `Pitch.md`

### Dupliziertes Alt-Repository im Unterverzeichnis

- `Smolit_AdminBot/`

Das Unterverzeichnis ist ein fast vollstaendiger Legacy-Doppelbestand und widerspricht dem aktuellen Zielbild besonders stark.

## 4. REVIEW-Faelle

Diese Faelle werden bewusst nicht blind geloescht:

- `DevPrompt.md`
  - lokal vorhanden, aber per `.gitignore` ausgeschlossen; kein Cleanup-Ziel in diesem PR
- untracked lokale Doku unter `docs/security/` und `docs/releases/`
  - keine Legacy-Artefakte; gehoeren nicht zu diesem Cleanup-Commit
- Low-Level-IPC-Testskripte unter `scripts/`
  - bleiben vorerst erhalten, obwohl `send_request.sh` intern `python3` nutzt
  - Begruendung: sie beschreiben das aktuelle v2-Protokoll, nicht das alte Python-System

## 5. Risiken beim Cleanup

- versehentliches Entfernen aktuell nuetzlicher Betriebsartefakte
- Entfernen von Dokumenten, die noch indirekt referenziert werden
- Entfernen kleiner, aber noch aktueller Testhilfen

Gegenmassnahmen:

- erst Referenzpruefung, dann Loeschung
- KEEP/REMOVE/REVIEW explizit dokumentieren
- nach dem Cleanup Volltest und Security Gate

## 6. Welche Doku angepasst werden muss

- `README.md`
  - Rust-Zielbild als einziges kanonisches Modell klarstellen
- `docs/cleanup/LEGACY_CLEANUP_REPORT.md`
  - dokumentiert final, was entfernt wurde und was bewusst blieb

## 7. Entscheidungsregel

- eindeutig Legacy und unreferenziert oder dem Zielbild widersprechend: REMOVE
- aktuell kanonisch oder Teil von Rust/Security/CLI/Release: KEEP
- unklar oder bewusst lokal/außerhalb des Cleanup-Scopes: REVIEW

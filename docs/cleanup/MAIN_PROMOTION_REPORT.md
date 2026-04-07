# Main Promotion Report

## 1. Ausgangslage: `dev` vs `main`

Pruefgrundlage:

- `git fetch --all --prune`
- `git diff --name-status origin/main..origin/dev`
- `git log --oneline --decorate --graph origin/main..origin/dev`
- `git log --oneline --decorate --graph origin/dev..origin/main`

Ergebnis:

- `origin/dev` enthaelt den vollstaendigen Rust-/Security-/CLI-/Cleanup-Stand
- `origin/main` enthaelt keine eigenen zusaetzlichen Commits gegenueber `origin/dev`
- `origin/main` ist damit nur der aeltere Legacy-Stand, waehrend `origin/dev` der bereinigte Zielstand ist

## 2. Welche Unterschiede bestanden

Auf `dev`, aber nicht auf `main`, liegen insbesondere:

- Rust-Produktivstand mit gehaertetem `adminbotd`
- `adminbotctl`
- systemd-/polkit-/Policy-/Security-Release-Gate-Artefakte
- Security- und CLI-Dokumentation
- Cleanup-Dokumentation

Auf `main`, aber auf `dev` entfernt, lagen insbesondere folgende Legacy-Artefakte:

- alter Python-/`rootbot`-/`root_bot`-Code
- `watchdog.py`, `test_bot.py`, `rootbot-cli.py`
- alte Docker-/Compose-/ELK-/Prometheus-Artefakte
- alte `rootbot.service`, `rootbot.apparmor`, `setup_security.sh`, `setup.py`
- veraltete Alt-Dokumentation und der doppelte Altbaum `Smolit_AdminBot/`
- `DevPrompt.md`

## 3. Promotion-Entscheidung

Die Promotion von `dev` nach `main` ist fachlich sinnvoll, weil:

- `dev` der bereinigte Zielstand ist
- `main` keine konkurrierenden neueren Inhalte hat
- keine ungeklaerten Branch-Konflikte vorliegen
- der neue Zielstand auf `dev` bereits den Security-/CLI-/Cleanup-Stand repraesentiert

## 4. Ob Promotion erfolgt ist

Ja.

- PR `#113` `Promote Rust AdminBot v2 from dev to main` wurde erstellt
- der Pflicht-Check `security-gate` lief auf dem PR gruen
- anschliessend wurde der PR sauber nach `main` gemerged

## 5. Ob `main` jetzt bereinigt ist

Vor der Promotion:

- nein, `main` war noch der aeltere Legacy-Stand

Nach der Promotion:

- ja, `main` zeigt jetzt das Rust-/AdminBot-v2-Zielbild
- `README.md` ist auf das neue Zielbild ausgerichtet
- `docs/security/*`, `docs/cli/*`, `docs/cleanup/*`, `docs/releases/*` sind vorhanden
- `adminbotd.service`, `deploy/polkit/*`, `scripts/verify_security_release_gate.sh` und `adminbotctl` sind auf `main` vorhanden

## 6. Ob noch Altartefakte auf `main` existieren

Vor der Promotion:

- ja, weil `main` den aelteren Stand repraesentierte

Nach der Promotion:

- keine getrackten `*.py`-Dateien mehr
- keine alten `rootbot`-/`root_bot`-/Watchdog-/Docker-/ELK-/Prometheus-/AppArmor-/Setup-Artefakte mehr
- einzig verbliebene Treffer sind dokumentierte historische Referenzen in `README.md`, `docs/adminbot_v2/*` und `docs/cleanup/*`
- `scripts/send_request.sh` nutzt weiterhin bewusst ein kleines `python3`-Inline-Snippet fuer das aktuelle v2-IPC-Framing; das ist keine alte Python-AdminBot-Implementierung

Fazit:

`main` ist jetzt frei von altem Python-/Legacy-AdminBot-Code und repraesentiert den aktuellen Rust-/AdminBot-v2-Stand.

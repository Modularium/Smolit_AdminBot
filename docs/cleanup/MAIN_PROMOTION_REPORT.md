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

Status zum Zeitpunkt der Dokumenterstellung:

- Promotion-PR von `dev` nach `main` wurde vorbereitet bzw. erstellt
- nach dem Merge ist explizit zu pruefen, dass `main` keine alten Python-/Legacy-Artefakte mehr enthaelt

## 5. Ob `main` jetzt bereinigt ist

Vor der Promotion:

- nein, `main` war noch der aeltere Legacy-Stand

Nach der Promotion:

- separat zu verifizieren

## 6. Ob noch Altartefakte auf `main` existieren

Vor der Promotion:

- ja, weil `main` den aelteren Stand repraesentierte

Nach der Promotion gilt als Ziel:

- `main` soll den gleichen Rust-/AdminBot-v2-Zielstand wie `dev` enthalten
- kein alter Python-/Legacy-AdminBot-Code soll auf `main` verbleiben


# AGENTS.md — AdminBot v2 Codex Execution Rules

## 🎯 Ziel

Dieses Dokument definiert, wie Codex im Repository arbeitet.

Ziel:
- deterministische Umsetzung der Architektur
- keine Scope-Drift
- kleine, saubere, reviewbare Changes
- vollständige GitHub-Integration (Issues → Branch → PR)

---

## 🚫 HARTE REGELN (NICHT VERLETZEN)

### Architektur
- KEINE Architekturänderungen
- KEINE neuen Features außerhalb der definierten v1 Actions
- KEIN Scope-Wachstum

### Security
- KEIN Shell-Zugriff (`exec`, `systemctl`, etc.)
- KEIN sudo
- KEIN Root-Daemon
- KEIN generischer Command-Runner

### Service Control
- `service.restart` ausschließlich über:
  - `org.freedesktop.systemd1.Manager.RestartUnit(unit, "replace")`
- KEIN Fallback
- KEIN alternativer Pfad

### Code Style
- Keine unnötigen Dependencies
- Keine "quick hacks"
- Kein Copy-Paste ohne Struktur

---

## 🧠 Arbeitsmodell

### Grundprinzip

```text
1 Issue = 1 Branch = 1 PR
````

Keine Ausnahmen.

---

## 🔄 Workflow

### 1. Issue auswählen

* Nur Issues ohne PR bearbeiten
* Priorität:

  1. prio:high
  2. nach Milestone-Reihenfolge

---

### 2. Branch erstellen

Naming:

```bash
feature/<scope>-<short-description>
```

Beispiele:

* `feature/ipc-socket`
* `feature/policy-engine`
* `feature/system-status`

---

### 3. Implementierung

* nur Scope des Issues
* keine "Nebenbei-Fixes"
* Code muss:

  * kompilieren
  * minimal testbar sein

---

### 4. Commit-Regeln

Format:

```text
feat(<scope>): <short description>
```

Beispiele:

* `feat(ipc): implement unix socket server`
* `feat(policy): add capability checks`

---

### 5. Pull Request

* Zielbranch: `dev`
* Merge: squash

PR muss enthalten:

* What was implemented
* Why
* Scope boundaries (was NICHT enthalten ist)
* Test-Hinweis

---

## 🧩 Implementierungs-Reihenfolge (VERBINDLICH)

1. IPC Foundation
2. Error Model + Types
3. Action Registry
4. Request Validator
5. Policy Engine
6. Read-only Actions
7. Audit Logger
8. service.restart (LETZTER SCHRITT)

---

## ⚠️ Kritische Regeln für Codex

### Reihenfolge ist Pflicht

* NIEMALS `service.restart` früh implementieren

### Keine impliziten Features

* nichts hinzufügen, was nicht im Issue steht

### Kein Refactoring ohne Issue

* nur implementieren

---

## 🧪 Tests (minimal v1)

Jeder PR muss:

* mindestens 1 funktionierenden Request zeigen
* Fehlerfall berücksichtigen

---

## 📁 Struktur beachten

Die Struktur aus ARCHITECTURE.md ist verbindlich:

```text
src/
  ipc/
  actions/
  policy/
  audit/
  system/
  backends/
```

---

## 🔐 Policy Awareness

* jede Action → Capability Check
* jede mutierende Action → Cooldown
* jede Aktion → Audit Log

---

## 🧾 Error Model (verbindlich)

Alle Fehler müssen:

```json
{
  "status": "error",
  "error": {
    "code": "...",
    "message": "...",
    "details": {},
    "retryable": false
  }
}
```

---

## 🧭 Definition of Done

Ein Issue ist fertig, wenn:

* Code kompiliert
* Scope exakt erfüllt ist
* PR erstellt ist
* keine Architektur verletzt wurde

---

## 🧠 Zielzustand

* kleiner, sicherer, auditierbarer Daemon
* keine versteckten Features
* keine impliziten Erweiterungen

---

## ❗ Wenn unsicher

Dann gilt:

> NICHT raten → Issue-Kommentar oder abbrechen

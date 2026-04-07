# adminbotctl

## Ziel

`adminbotctl` ist die minimale Operator-CLI fuer AdminBot v1.x.

Sie ist:

- ein kontrollierter lokaler Einstiegspunkt
- kein zweiter Verwaltungs-Backend-Pfad
- kein Shell-Wrapper
- kein Ersatz fuer Policy, Gate oder Audit

## Prinzipien

### Read-only first

- Standardnutzung ist lesend
- mutierende Operationen bleiben explizit, selten und deutlich getrennt

### Explicit over implicit

- jeder sicherheitsrelevante Modus wird explizit angegeben
- keine versteckten Fallbacks
- keine Magie aus Umgebungszustand oder stillen Defaults

### No dangerous defaults

- keine mutierende Aktion ohne bewusste Bestätigung
- kein automatisches Reparieren
- kein stilles Ignorieren von Fehlern oder Security-Drift

### Keine zweite API

- `adminbotctl` nutzt bestehende AdminBot-Schnittstellen und vorhandene Validierung
- Sicherheitslogik bleibt im Core oder im Security-Gate
- die CLI formatiert, bestätigt und validiert Eingaben, sie ersetzt keine Policy

## Finale Command Surface

Globale Option fuer IPC-basierte Commands:

```text
--socket PATH
```

Default:

- `/run/adminbot/adminbot.sock`

### Read-only

```text
adminbotctl status [--json]
adminbotctl health [--json]
adminbotctl policy validate [--path PATH] [--json]
adminbotctl gate run --mode artifact|live [--policy PATH] [--polkit PATH] [--unit PATH] [--runtime-dir PATH] [--socket PATH] [--expected-polkit-template PATH] [--json]
adminbotctl audit tail [--unit UNIT] [--priority-min warning|error|critical] [--since-seconds N] [--limit N] [--show-message] [--json]
```

### Mutierend

```text
adminbotctl restart --unit UNIT --reason TEXT [--dry-run] [--confirm] [--json]
```

## Nicht Teil der CLI

Nicht vorgesehen:

- generische Request-Einspeisung
- Raw-JSON-Passthrough
- automatische Policy-Reparatur
- automatische polkit- oder systemd-Änderungen
- direkte Shell-Kommandos

## Sicherheitsregeln

### status

- mappt auf `system.status`
- keine Seiteneffekte
- Human-Default zeigt nur kompakten Zustand

### health

- mappt auf `system.health`
- keine Seiteneffekte
- Human-Default zeigt nur Status und Checks

### policy validate

- validiert lokal das Policy-Artefakt
- laedt die Policy vollstaendig, damit syntaktische und semantische Fehler sichtbar werden
- fuer den Standardpfad `/etc/adminbot/policy.toml` werden zusaetzlich dieselben Deployment-Invarianten wie beim Daemon-Start geprueft
- fuer explizite Custom-Pfade werden Owner/Mode nicht implizit als Deployment-Check erzwungen; der Befehl prueft dort bewusst Syntax und Semantik des Policy-Artefakts
- macht keine automatischen Fixes

### gate run

- ist die CLI-Oberflaeche fuer denselben Security Release Gate Vertrag
- ist die kanonische Implementierung des Gates; `scripts/verify_security_release_gate.sh` delegiert absichtlich an diesen Befehl
- `artifact` prueft versionierte Repo-Artefakte
- `live` prueft installierte Zielsystem-Artefakte
- `FAIL` bleibt `FAIL`, kein Soft-Bypass

### audit tail

- nutzt die bestehende Action `journal.query`
- ist read-only, aber sensitiv
- Human-Default zeigt Metadaten kompakt
- Message-Inhalt bleibt ohne `--show-message` oder `--json` redacted
- Default-Unit ist `adminbotd.service`
- andere Units muessen explizit per `--unit` angefordert werden

### restart

- ist optionaler, kontrollierter Operator-Pfad ueber die bestehende Action `service.restart`
- Pflicht:
  - `--unit`
  - `--reason`
- ohne `--confirm`:
  - bei interaktivem TTY erfolgt eine explizite Bestätigung
  - ohne TTY wird die Aktion abgelehnt
- keine stillen Neustarts
- keine Sammel- oder Massenoperationen
- `--dry-run` bleibt explizit und aendert nichts

## Output-Design

### Default

- menschenlesbar
- kurz
- keine unnötigen Rohdaten
- keine sensiblen Journal-Messages im Default

### JSON

- `--json` gibt die strukturierte Maschinenantwort aus
- JSON ist fuer Skripte gedacht und darf mehr Detail tragen als der Human-Default
- Fehler bleiben maschinenlesbar und deterministisch

## Human Output pro Command

### status

- Hostname
- Kernel
- Uptime
- Load
- Speicherübersicht

### health

- Overall Status
- Liste der Checks mit Status
- Warnings, wenn vorhanden

### policy validate

- `PASS` oder `FAIL`
- Pfad
- bei Fehlern: konkrete Ursache

### gate run

- `PASS` oder `FAIL`
- pro Check eine eigene Zeile
- am Ende klarer Gesamtausgang

### audit tail

Default ohne `--show-message`:

- Timestamp
- Unit
- Priorität
- `message_redacted=true`

Mit `--show-message`:

- zusätzlich Message-Inhalt

### restart

- Dry-Run: klare Vorschau ohne Seiteneffekt
- echter Neustart:
  - Unit
  - Mode
  - Job-Object-Path
  - Pre-State
  - Post-State

## Sichere Defaults

- Socket-Pfad default: `/run/adminbot/adminbot.sock`
- Policy-Pfad default: `/etc/adminbot/policy.toml`
- Gate-Modus hat **keinen** impliziten Default im CLI-Subcommand und muss explizit angegeben werden
- `audit tail` Default:
  - `--unit adminbotd.service`
  - `--since-seconds 900`
  - `--limit 20`
  - kein impliziter Prioritaetsfilter
  - Message redacted

## Fehlerverhalten

- keine stillen Retries fuer mutierende Aktionen
- keine automatische Eskalation
- CLI gibt Fehler mit klarer Ursache zurueck
- Policy- oder Gate-Fehler fuehren zu Exit-Code ungleich `0`

## Typische Nutzung

### Host-Status

```bash
adminbotctl status
adminbotctl status --json
```

### Policy pruefen

```bash
adminbotctl policy validate
adminbotctl policy validate --path ./config/policy.example.toml --json
```

### Security Gate

```bash
adminbotctl gate run --mode artifact
adminbotctl gate run --mode live
```

### Audit ansehen

```bash
adminbotctl audit tail
adminbotctl audit tail --unit adminbotd.service --since-seconds 3600 --limit 50
adminbotctl audit tail --show-message
```

### Neustart bewusst ausloesen

```bash
adminbotctl restart --unit nginx.service --reason "manual operator restart" --dry-run
adminbotctl restart --unit nginx.service --reason "manual operator restart" --confirm
```

## Typische Fehler

- Socket nicht erreichbar
  - Daemon laeuft nicht oder Runtime-Pfad ist falsch
- Policy validate failt
  - Rechte, Owner oder TOML-Inhalt sind ungueltig
- Gate failt
  - Repo- oder Zielsystem-Artefakte driften vom Sicherheitsvertrag ab
- audit tail liefert `policy_denied` oder `capability_denied`
  - lokale Unix-Identitaet hat kein `read_sensitive`
- restart wird ohne TTY und ohne `--confirm` abgewiesen
  - bewusstes Schutzverhalten gegen unbeabsichtigte Mutation

## Production-Readiness-Kriterium

`adminbotctl` ist erst dann production-ready, wenn:

- alle Commands deterministisch sind
- keine Sicherheitslogik dupliziert wird
- mutierende Nutzung nicht still moeglich ist
- Gate und Policy-Checks denselben Sicherheitsvertrag wie Daemon und Release nutzen

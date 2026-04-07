# AdminBot v2 IPC Spezifikation

## Ziel und Scope

Die primäre lokale Schnittstelle des AdminBot ist ein Unix Domain Socket. Sie dient:

- lokaler CLI-Nutzung
- späterer lokaler Nutzung durch einen `Agent-NN`-nahen Integrationsprozess
- strukturierter, typisierter Interaktion ohne freie Shell

Nicht Ziel:

- generische Remote-API
- offene Netzwerksteuerung
- Web-UI-Protokoll

## Transport-Festlegung

- Transport: Unix Domain Socket
- Socket-Pfad: `/run/adminbot/adminbot.sock`
- Encoding: JSON in UTF-8
- Framing: length-prefixed

## Framing-Entscheidung

Für `v1` wird `length-prefixed` verbindlich festgelegt.

Format:

- 4 Byte unsigned big-endian Länge
- danach exakt so viele Bytes JSON-Payload

Begründung:

- robuster als newline-delimited JSON
- unproblematisch bei mehrzeiligen Strings
- klare Implementierbarkeit in Rust
- deterministische Parser-Logik

newline-delimited JSON wird für `v1` nicht verwendet.

## Socket-Modell

- Typ: Unix Domain Socket
- Eigentümer: `adminbot:adminbotctl`
- Modus: `0660`
- nur lokaler Zugriff
- Peer-Credentials werden geprüft

Grundsatz:

- Socket-Zugriff ist nur die technische Eintrittsschwelle
- Action-Zugriff wird zusätzlich durch Policy und Capability entschieden

## Request-Modell

## Pflichtfelder

- `version`
- `request_id`
- `requested_by`
- `action`
- `params`
- `dry_run`
- `timeout_ms`

## Bedingt verpflichtend

- `reason`
  - Pflicht bei mutierenden Aktionen

## Optionale Felder

- `correlation_id`
- `requested_capability`
- `explain`
- `preflight_only`

## Request-Schema

```json
{
  "version": 1,
  "request_id": "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62571",
  "correlation_id": "incident-2026-04-06-001",
  "requested_by": {
    "type": "human",
    "id": "local-cli",
    "display_name": "adminbotctl"
  },
  "action": "service.restart",
  "params": {
    "unit": "nginx.service",
    "mode": "safe",
    "reason": "Healthcheck failed repeatedly"
  },
  "dry_run": true,
  "timeout_ms": 5000,
  "reason": "Healthcheck failed repeatedly",
  "requested_capability": "service_control",
  "explain": false,
  "preflight_only": false
}
```

## Felddefinitionen

### `version`

- Typ: integer
- Pflicht: ja
- aktuell erlaubter Wert: `1`
- unbekannte Version führt zu `unsupported_version`

### `request_id`

- Typ: UUID string
- Pflicht: ja
- muss pro Request eindeutig sein
- fuer mutierende Non-Dry-Run-Requests gilt `request_id` zusaetzlich als kurzlebiger Idempotency-Key
- identische Replays derselben mutierenden Anfrage koennen innerhalb des Replay-Fensters denselben Response zurueckliefern
- Wiederverwendung derselben `request_id` mit anderem mutierenden Payload ist unzulaessig

### `correlation_id`

- Typ: string
- Pflicht: nein
- dient Incident-, Session- oder Agent-Lauf-Korrelation

### `requested_by`

- Typ: object
- Pflicht: ja

Felder:

- `type`
  - Pflicht
  - Werte: `human`, `agent`, `system`
- `id`
  - Pflicht
  - stabiler Bezeichner
- `display_name`
  - optional

### `action`

- Typ: string
- Pflicht: ja
- muss exakt einer Action aus der Registry entsprechen

### `params`

- Typ: object
- Pflicht: ja
- Schema hängt von `action` ab

### `dry_run`

- Typ: boolean
- Pflicht: ja

### `timeout_ms`

- Typ: integer
- Pflicht: ja
- Wertebereich gemäß Policy, z.B. `100..30000`

### `reason`

- Typ: string
- Pflicht: für mutierende Aktionen
- optional für read-only Aktionen

### `requested_capability`

- Typ: string
- Pflicht: nein
- deklarative Selbstaussage des Clients
- autoritativ bleibt die lokale Policy

### `explain`

- Typ: boolean
- Pflicht: nein
- liefert kurze strukturierte Entscheidungsbegründung

### `preflight_only`

- Typ: boolean
- Pflicht: nein
- Validierung, Policy und Precondition ja, Ausführung nein

## Response-Modell

## Erfolgsresponse Pflichtfelder

- `request_id`
- `action`
- `status`
- `warnings`
- `audit_ref`
- `duration_ms`
- `error`

## Erfolgsresponse optionale Felder

- `correlation_id`
- `result`
- `explain`

## Fehlerresponse Pflichtfelder

- `request_id`
- `status`
- `error`

## Fehlerresponse optionale Felder

- `correlation_id`
- `action`
- `audit_ref`
- `duration_ms`

## Response-Schema

```json
{
  "request_id": "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62571",
  "correlation_id": "incident-2026-04-06-001",
  "action": "service.restart",
  "status": "dry_run_ok",
  "result": {
    "unit": "nginx.service",
    "mode": "safe",
    "pre_state": {
      "active_state": "active",
      "sub_state": "running"
    },
    "would_restart": true
  },
  "warnings": [
    "restart_is_non_idempotent"
  ],
  "audit_ref": "audit-2026-04-06-000231",
  "duration_ms": 14,
  "error": null
}
```

## Statuswerte

- `ok`
- `dry_run_ok`
- `preflight_ok`
- `rejected`
- `failed`
- `error`

## Fehlerobjekt

```json
{
  "request_id": "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62571",
  "status": "error",
  "error": {
    "code": "policy_denied",
    "message": "unit not allowed by policy",
    "details": {
      "field": "params.unit",
      "policy_section": "service_control.allowed_units"
    },
    "retryable": false
  }
}
```

## Globales Fehlermodell

Für `v1` wird folgendes Fehlerformat verbindlich festgelegt:

- `request_id`
  - Pflicht
  - referenziert den auslösenden Request
- `status`
  - Pflicht
  - bei Fehlern immer exakt `error`
- `error.code`
  - Pflicht
  - stabiler maschinenlesbarer Fehlercode
- `error.message`
  - Pflicht
  - kurze menschenlesbare Fehlerbeschreibung
- `error.details`
  - Pflicht
  - Objekt mit strukturierten Zusatzinformationen
- `error.retryable`
  - Pflicht
  - boolean zur Steuerung von CLI, Agent-NN und späterer UI

Optionale Felder auf Fehlerresponses:

- `correlation_id`
- `action`
- `audit_ref`
- `duration_ms`

Begründung:

- CLI kann zwischen Nutzerfehler, Policy-Ablehnung und technischem Problem unterscheiden
- `Agent-NN` kann retrybare Fehler anders behandeln als finale Ablehnungen
- spätere UIs bekommen stabile, maschinenlesbare Fehlerklassen statt freier Textanalyse

## Stabile v1-Fehlercodes

- `validation_error`
  - Request oder Parameter formal ungültig
- `unsupported_version`
  - unbekannte oder nicht unterstützte Protokollversion
- `unauthorized`
  - Client-Herkunft oder Peer-Credentials nicht akzeptiert
- `forbidden`
  - generische Verbotsklasse, nur wenn kein präziserer Code passt
- `capability_denied`
  - Client besitzt die geforderte Capability nicht
- `policy_denied`
  - Aktion oder Parameter laut Policy nicht erlaubt
- `precondition_failed`
  - Aktion erlaubt, aber aktueller Zustand verhindert Ausführung
- `cooldown_active`
  - Aktion wegen Cooldown abgelehnt
- `rate_limited`
  - lokale Schutzgrenze überschritten
- `backend_unavailable`
  - erforderliches Backend wie systemd D-Bus oder journald derzeit nicht verfügbar
- `execution_failed`
  - Aktion technisch fehlgeschlagen
- `timeout`
  - Ausführung überschritt Zeitbudget

## Beispiel Request als Frame

Konzeptionell:

```text
[4-byte length][json payload bytes]
```

JSON-Payload:

```json
{
  "version": 1,
  "request_id": "fbe7b4d9-47af-4f6b-b8b1-df9d6d981f0b",
  "requested_by": {
    "type": "agent",
    "id": "agentnn-adminbot-agent"
  },
  "action": "service.status",
  "params": {
    "unit": "nginx.service"
  },
  "dry_run": false,
  "timeout_ms": 3000,
  "requested_capability": "service_read"
}
```

## Beispiel Response vollständig

```json
{
  "request_id": "fbe7b4d9-47af-4f6b-b8b1-df9d6d981f0b",
  "action": "service.status",
  "status": "ok",
  "result": {
    "unit": "nginx.service",
    "active_state": "active",
    "sub_state": "running",
    "load_state": "loaded",
    "unit_file_state": "enabled",
    "timestamp": "2026-04-06T12:00:00Z"
  },
  "warnings": [],
  "audit_ref": "audit-2026-04-06-000232",
  "duration_ms": 8,
  "error": null
}
```

## Semantische Garantien

Die IPC soll folgende Garantien bieten:

- keine freie Shell-Semantik
- jede Anfrage referenziert genau eine registrierte Action
- jede Antwort enthält klaren Status und Audit-Referenz
- `dry_run` führt keine Seiteneffekte aus
- `preflight_only` führt keine Seiteneffekte aus
- idempotente und nicht-idempotente Aktionen werden in der Registry definiert, nicht implizit erraten

Wichtig:

- `dry_run` ist keine bloße Textsimulation
- `preflight_only` prüft zusätzlich technische Preconditions
- `explain` liefert knappe strukturierte Begründungen, aber keine sensiblen internen Details

## Versionierung und Abwärtskompatibilität

- Protokollversion im Feld `version`
- `version` ist Pflichtfeld
- `1` ist die initiale stabile Version
- additive optionale Felder sind erlaubt
- Breaking Changes nur über neue Hauptversion
- unbekannte optionale Felder sollen ignorierbar sein
- unbekannte Pflichtfelder oder Versionen führen zu `unsupported_version` oder `validation_error`

Begründung:

- Integer-Versionen sind kompakt, sprachneutral und direkt vergleichbar
- die Semantik bleibt klarer als bei freier String-Versionierung

## Sicherheits- und Audit-Anforderungen

- jede Anfrage braucht `request_id`
- mutierende Aktionen brauchen `reason`
- `requested_by.type` muss zwischen `human`, `agent`, `system` unterscheiden
- `agent`-Requests werden separat markiert
- sensible Parameter dürfen im Audit maskiert werden
- Antworten sollen keine unnötigen internen Pfade oder Rohfehler offenlegen

## Architektur-Fazit

Die IPC ist nicht nur Transport, sondern Sicherheitsgrenze. Mit Unix Domain Socket, JSON und length-prefixed Framing ist das Protokoll für `v1` ausreichend konkret, robust und direkt implementierbar, ohne das Grundprinzip der schmalen lokalen Vertrauensgrenze aufzuweichen.

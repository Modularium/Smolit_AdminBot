# AdminBot Defense in Depth

## Zweck

Dieses Dokument fasst die Defense-in-Depth-Massnahmen zusammen, die ueber die unmittelbaren P0/P1-Sicherheitsfixes hinausgehen. Ziel ist keine neue Trust Boundary, sondern eine engere und besser beobachtbare Absicherung derselben lokalen Architektur.

## Leitprinzipien

- konservative Defaults bleiben konservativ
- zusaetzliche Haertung ist entweder explizit opt-in oder strikt fail-safe
- keine Sicherheitslogik wird in Convenience-Pfade dupliziert
- deterministische Limits sind wertvoller als adaptive Heuristiken

## Phase 3 Bausteine

### 1. Global Rate Limiting

- kombiniert globale und peer-bezogene Fenster
- trennt Read- und Mutate-Requests
- haertet nicht nur den IPC-Eingang, sondern den gesamten Request-Lebenszyklus

Echter Sicherheitsgewinn:

- reduziert CPU- und Backend-Amplification durch gueltige, aber uebermaessige Requests
- erschwert koordinierte lokale Floods ueber mehrere Clients

Bewusste Nicht-Ziele:

- kein verteiltes Rate-Limiting
- keine adaptive oder lernende Throttling-Logik

### 2. Action Scoping Refinement

- trennt breite Legacy-Capabilities in engere Freigaben
- `journal.query` kann explizit enger als `service_control.allowed_units` gescoped werden

Echter Sicherheitsgewinn:

- verringert den Explosionsradius bei Fehlvergabe einzelner Capabilities
- macht Least Privilege reviewbarer

Bewusste Nicht-Ziele:

- keine neuen Trust Boundaries
- keine impliziten Freigaben fuer neue Actions

### 3. High Security Mode

- optionales engeres Profil fuer Rate-Limits und Replay-Fenster
- veraendert nichts stillschweigend fuer Standard-Deployments

Echter Sicherheitsgewinn:

- erlaubt besonders gehaerteten Installationen strengere Betriebsgrenzen ohne Fork der Architektur

Bewusste Nicht-Ziele:

- kein versteckter "Paranoid Mode"
- keine unkommentierten Verhaltensaenderungen

### 4. Observability Hardening

- Audit bleibt strukturiert
- Operator-IDs koennen optional gehasht statt im Klartext geloggt werden

Echter Sicherheitsgewinn:

- reduziert Datenabfluss ueber journald und Fallback-Logs
- erhaelt Korrelation fuer Incident Response

Bewusste Nicht-Ziele:

- keine neue Audit-Pipeline
- keine kryptographische Log-Chain

### 5. Misconfiguration Guards

- syntaktisch valide, aber riskante Policy-Konfigurationen werden als Sanity-Warnungen sichtbar
- `fail_on_sanity_warnings` kann diese Warnungen in einen harten Startup-Blocker verwandeln
- ausgehende IPC-Responses werden auf dieselbe feste Frame-Grenze wie eingehende Requests begrenzt

Echter Sicherheitsgewinn:

- reduziert Sicherheitsdrift durch zu breite Policy-Freigaben
- verhindert unbounded Antwortpfade trotz bereits gehaerteter Eingangsgrenzen

Bewusste Nicht-Ziele:

- keine heuristische Policy-Scoring-Engine
- kein neues Transportprotokoll fuer grosse Responses

## Was echten Sicherheitsgewinn bringt

- harte, kleine und nachvollziehbare technische Grenzen
- explizite Policy-Scopes fuer sensitive Read- und Mutate-Rechte
- opt-in Haertung statt stiller Magie
- reproduzierbare Release- und Startup-Checks

## Was nur theoretisch waere

- adaptive Abwehrlogik ohne klare Grenzwerte
- generische Policy-Linter mit schwer nachvollziehbaren Regeln
- umfangreiche Kryptographie fuer Logs ohne passende Betriebsintegration
- neue Protokolle oder Neben-APIs fuer Spezialfaelle

## Betriebsfolgen

- Operatoren sollten `adminbotctl policy validate` als Pflichtschritt vor Rollout nutzen
- besonders gehärtete Systeme sollten `security_profile = "high_security"` und bei Bedarf `fail_on_sanity_warnings = true` setzen
- Broad-Scope-Policy-Warnungen sind kein Rauschen; sie sind gezielte Review-Hinweise fuer Least-Privilege-Nachhaertung

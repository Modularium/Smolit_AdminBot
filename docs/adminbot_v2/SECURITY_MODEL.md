# AdminBot v2 Sicherheitsmodell

## Zielbild

`AdminBot v2` ist ein lokaler, minimaler Executor mit harter Policy-Grenze. Sicherheit entsteht nicht aus “smarten” Entscheidungen, sondern aus:

- kleinem Scope
- fester Action Registry
- lokaler IPC
- engem Privilegmodell
- strukturierter Auditierung

## Bedrohungsmodell

### Zu schützende Güter

- lokale Systemintegrität
- Dienstverfügbarkeit
- Service-Steuerung
- Diagnose- und Journaldaten
- Nachvollziehbarkeit von Admin-Aktionen

### Wahrscheinliche Bedrohungen

- Missbrauch des lokalen IPC durch unberechtigte Benutzer
- zu breite oder fehlerhafte Policy-Freigaben
- Kommandoinjektion über freie Shell-Pfade
- Privilegieneskalation über zu breite Rechte oder eigene Root-Pfade
- Agentenfehlverhalten oder Endlosschleifen aus `Agent-NN`
- unvollständige Audit-Ketten bei mutierenden Aktionen

### Explizit zu vermeiden

- generische Shell-Ausführung
- dynamische Laufzeit-Plugins im Core
- Auto-Downloads externer Artefakte
- Docker-Socket-Zugriff im Core
- Vermischung von Denklogik und privilegierter Ausführung

## Privilegmodell

## Grundsatz

- non-root als Default
- Privilegien pro Aktion minimieren
- der Normalfall ist read-only
- mutierende Aktionen werden gesondert begründet, freigegeben und auditierbar gemacht

## Verbindliche v1-Festlegung

- `adminbotd` läuft als Systembenutzer `adminbot`
- `adminbotd` läuft nicht als Root
- lokale Clients nutzen weiterhin die Gruppe `adminbotctl`
- Service-Control erfolgt in `v1` primär über systemd D-Bus plus polkit
- polkit dient dabei nur als schmale System-Privilegbrücke
- die fachliche Entscheidung bleibt in `adminbotd` bei Policy, Capability, Whitelist und Cooldown
- `Agent-NN` erhält in `v1` weiterhin keine `service_control`-Capability
- kein generischer Root-Helper im Standardpfad
- Linux Capabilities sind nicht der primäre Mechanismus für `service.restart`
- `requested_by.type` und `requested_by.id` sind in `v1.x` keine vertrauenswuerdige Autorisierungsquelle
- Rollenunterschiede zwischen Human und Agent muessen ueber getrennte Unix-User oder Unix-Gruppen modelliert werden, nicht ueber selbstdeklarierte Request-Metadaten

## Bewertung der Service-Control-Optionen

### Option A: systemd D-Bus plus polkit

Vorteile:

- systemnahe und fachlich passende Privilegvermittlung
- kein Root-Daemon nötig
- klare Bindung an Service-Management statt freie Macht
- gute Nachvollziehbarkeit zusammen mit AdminBot-Audit

Nachteile:

- zusätzliche Integrationsarbeit
- polkit-Regeln müssen sauber und eng formuliert werden
- die Systemaktion ist grober als AdminBot selbst und muss deshalb durch lokale Policy und feste D-Bus-Semantik nachgeschaerft werden

Entscheidung:

- Primary für `v1`
- verbindliche technische Ausprägung:
  - Interface `org.freedesktop.systemd1.Manager`
  - Methode `RestartUnit`
  - systemd-Mode nur `"replace"`
  - AdminBot-Mode nur `safe`
  - Mapping `safe -> RestartUnit(unit, "replace")`
  - polkit-Aktions-ID `org.freedesktop.systemd1.manage-units`
  - versionierte polkit-Regelvorlage im Repository unter `deploy/polkit/50-adminbotd-systemd.rules`
- nicht Teil von `v1`:
  - kein `systemctl`
  - kein Shell-Fallback
  - kein alternativer Restart-Pfad
  - kein komplexes asynchrones Job-Framework

### Option B: dedizierter Root-Helper

Vorteile:

- technisch kontrollierbar, wenn extrem klein
- kann als gezielter Escape-Hatch dienen

Nachteile:

- eigener privilegierter Codepfad
- höherer Wartungs- und Review-Aufwand
- Gefahr schleichender Scope-Ausweitung

Entscheidung:

- nur Reserveoption
- nicht Teil des `v1`-Normalpfads

### Option C: Linux Capabilities

Vorteile:

- attraktiv auf den ersten Blick

Nachteile:

- für systemd-Service-Steuerung fachlich unpassend
- schlechte Granularität
- keine saubere Modellierung einzelner Service-Aktionen

Entscheidung:

- verworfen als Primärstrategie für `v1`

## Minimaldesign eines privilegierten Helpers

Da ein Helper als Reserveoption dokumentiert werden soll, gilt folgendes Minimaldesign:

### Verantwortungsbereich

- ausschließlich Service-Control
- konkret nur:
  - `restart_unit`
  - optional später `start_unit`, `stop_unit`

### API-Regeln

- nur strukturierte Inputs
- kein Shell-String
- keine arbitrary Pfade
- keine Subcommands
- kein freier D-Bus- oder systemctl-Passthrough

Beispielhafter interner Request:

```json
{
  "op": "restart_unit",
  "unit": "nginx.service",
  "mode": "safe",
  "request_id": "uuid",
  "correlation_id": "string"
}
```

### Kommunikationsmodell

- nur interner lokaler Kanal zwischen `adminbotd` und Helper
- nicht direkt für CLI oder `Agent-NN`
- eigener kleiner, nicht öffentlicher Vertrag

### Sicherheitsregeln

- Unit-Name muss bereits durch `adminbotd` validiert und policy-geprüft sein
- Helper prüft Whitelist dennoch erneut defensiv
- Helper darf keine neue Policy-Logik erfinden
- jede Helper-Nutzung wird von `adminbotd` und Helper selbst auditiert

### Minimalrechte

- nur Neustart freigegebener Systemd-Units
- keine Paketverwaltung
- keine Benutzerverwaltung
- keine Dateisystemschreibrechte außerhalb eigener minimaler Laufzeitbedürfnisse

## Policy-Modell v1

Für `v1` wird ein kleines TOML-Format festgelegt.

Ziele:

- einfach
- statisch ladbar
- menschenlesbar
- ohne Policy-Engine-Overengineering

## Beispiel Policy-Datei

```toml
version = 1

[clients.local_cli]
unix_group = "adminbotctl"
allowed_capabilities = ["read_basic", "read_sensitive", "service_read", "service_control"]

[clients.agentnn_adminbot]
unix_user = "agentnn"
allowed_capabilities = ["read_basic", "read_sensitive", "service_read"]

[actions]
allowed = [
  "system.status",
  "system.health",
  "resource.snapshot",
  "disk.usage",
  "network.interface_status",
  "service.status",
  "journal.query",
  "process.snapshot",
  "service.restart",
]
denied = []

[filesystem]
allowed_mounts = ["/", "/var"]

[service_control]
allowed_units = ["nginx.service", "ssh.service"]
restart_cooldown_seconds = 300
max_restarts_per_hour = 3

[constraints]
default_timeout_ms = 5000
max_timeout_ms = 30000
journal_limit_max = 200
process_limit_max = 50
max_parallel_mutations = 1
```

## Struktur der Policy

### `clients.*`

Definiert, welche lokalen Clients welche Capabilities bekommen.

Mögliche Match-Kriterien in `v1`:

- `unix_user`
- `unix_group`

Nicht fuer Autorisierung vertrauenswuerdig in `v1.x`:

- `requested_by.type`
- `requested_by.id`
- `allowed_request_types` als alleinige Rollentrennung fuer dieselbe OS-Identitaet

### Deployment-Invariante fuer die Policy-Datei

- `/etc/adminbot/policy.toml` ist ein sicherheitskritisches Artefakt
- `adminbotd` startet fail closed, wenn die Datei
  - nicht root-owned ist
  - group-writable ist
  - world-writable ist
  - kein regulaeres File ist

### Deployment-Invariante fuer Runtime-Verzeichnis und Socket

- `/run/adminbot` ist ein sicherheitskritisches Laufzeit-Artefakt
- `adminbotd` startet fail closed, wenn
  - `/run/adminbot` nicht als echtes Verzeichnis vorliegt
  - Owner oder Gruppe nicht zur Service-Identitaet passen
  - der Modus nicht `0750` ist
  - unter `/run/adminbot/adminbot.sock` ein nicht vertrauenswuerdiges Alt-Artefakt liegt
- der Socket selbst muss nach dem Bind als Unix-Socket mit Owner `adminbot`, Gruppe `adminbotctl` und Modus `0660` vorliegen

### `actions`

Globale Positivliste für den Daemon.

### `filesystem`

- kleine statische Whitelist fuer read-only Mountpoints
- `allowed_mounts` definiert die einzigen fuer `disk.usage` erlaubten Mountpoints in `v1`
- keine freie Dateisystemauswahl

### `service_control`

- Whitelist der erlaubten Units
- Cooldowns
- Restart-Rate-Limits
- keine freie systemd-Action
- keine generische polkit-basierte Root-Eskalation

### `constraints`

- globale technische Limits
- `max_parallel_mutations` wird fuer mutierende Non-Dry-Run-Requests aktiv zur Laufzeit erzwungen
- keine komplexe Regelsprache in `v1`

## Privilegierte Aktionsklassen

- read-only Statusabfragen
  - möglichst ohne Root
- sensible Lesezugriffe
  - erweiterte lokale Einsicht, aber kein mutierender Backend-Pfad
- Service-Restart
  - kontrolliert, whitelisted und nur über privilegierten Backend-Adapter

## systemd Hardening

Folgende Optionen sind für den Hauptdienst realistisch und sinnvoll:

### `NoNewPrivileges=true`

- klar empfohlen
- verhindert nachträgliche Privilegienausweitung

### `PrivateTmp=true`

- empfohlen

### `PrivateDevices=true`

- empfohlen, solange kein Gerätezugriff benötigt wird

### `ProtectSystem=strict`

- bevorzugt
- Schreibpfade nur explizit per `ReadWritePaths=`

### `ProtectHome=true`

- empfohlen

### `MemoryDenyWriteExecute=true`

- empfohlen

### `RestrictAddressFamilies=AF_UNIX`

- Zielwert für `v1`
- systemd D-Bus und polkit müssen explizit gegen diese Härtung verifiziert werden
- nur falls technisch zwingend nötig, darf minimal und begründet erweitert werden
- das ist ein Implementierungs- und Verifikationspunkt, kein offener Architekturstreit mehr

### `SystemCallFilter=`

- empfohlen
- restriktive Basis, dann nur notwendige Freigaben

### `CapabilityBoundingSet=`

- im Hauptdienst möglichst leer

### `RestrictRealtime=true`

- empfohlen

### `LockPersonality=true`

- empfohlen

### `MemoryMax=`

- empfohlen
- bewusst konservativ für RasPi- und Low-End-Tauglichkeit

### `CPUQuota=`

- empfohlen
- als Schutz gegen Fehlverhalten

## Lokale IPC-Sicherheit

## Socket-Rechte

- Pfad: `/run/adminbot/adminbot.sock`
- Eigentümer: `adminbot`
- Gruppe: `adminbotctl`
- Modus: `0660`

## Peer Credential Checks

Der Dienst prüft über `SO_PEERCRED` oder äquivalente Mechanismen:

- UID
- GID
- PID

Diese Daten fließen in:

- Capability-Zuordnung
- Audit
- Rate-Limits

## Lokale Vertrauensgrenze

- Socket-Zugriff ist nur lokal
- Gruppenmitgliedschaft allein genügt nicht
- Action-Zugriff ergibt sich aus Policy plus Request-Kontext plus Precondition

## Missbrauchsschutz

- Rate-Limits auf IPC-Ebene
- enge `timeout_ms`-Grenzen
- nur eine parallele mutierende Aktion in `v1`
- Cooldowns auf `service.restart`

## Audit und Nachvollziehbarkeit

## Auditpflichtige Felder

Mindestens zu loggen:

- Zeitstempel
- `request_id`
- `correlation_id`
- `requested_by.type`
- `requested_by.id`
- Peer UID/GID/PID
- Aktion
- gekürzte oder maskierte Parameter
- Dry-Run / Preflight / Explain
- Policy-Entscheidung
- Precondition-Ergebnis
- Ergebnisstatus
- Dauer
- Fehlercode
- verwendeter privilegierter Backend-Pfad

## Korrelation

- `request_id` identifiziert genau einen AdminBot-Request
- `correlation_id` verknüpft mehrere Requests zu Incident, Task oder Agent-Lauf
- `audit_ref` kommt in jede Response

## Menschlich vs maschinell

Jeder Request wird im Audit markiert als:

- `human`
- `agent`
- `system`

Für `agent`-Requests zusätzlich sinnvoll:

- Herkunftskomponente, z.B. `agentnn-adminbot-agent`
- optionale Agent-Run-ID oder Session-ID

## Sicherheitsgrenzen gegenüber Agent-NN

### Grundsatz

- `Agent-NN` darf anfragen, aber nicht herrschen
- `Agent-NN` bekommt keinen Shell-Bypass
- `AdminBot` prüft lokal jede Anfrage
- polkit ist keine Agent-NN-Eskalationsfläche, sondern nur eine schmale Systembrücke für den Service-Control-Pfad
- die polkit-Vorlage darf nur den Service-User `adminbot` zulassen; Endnutzer bleiben auf die lokale IPC-Grenze beschränkt

### Konkrete Grenze

- `Agent-NN` spricht nur über dedizierte Tools
- dedizierte Tools mappen auf feste `AdminBot`-Actions
- `AdminBot` akzeptiert keine generischen Kommandos, Skripte oder Pfade
- `Agent-NN` bekommt in `v1` keine `service_control`-Capability

### Lokale Entscheidungshoheit

Nur `AdminBot` entscheidet lokal anhand von:

- Action Registry
- Policy
- Capability
- Precondition
- Rate-Limit
- Cooldown
- Laufzeitstatus

## No-Go-Patterns

Diese Muster sind für `AdminBot v2` ausdrücklich verboten:

- `shell=true`
- `run command` oder `exec command`
- generische Dateisystem-Schreib-API
- generische HTTP-Plugin-API im Core
- Auto-Update im laufenden Dienst
- Modell- oder Skriptdownload zur Laufzeit
- Docker-Socket-Zugriff
- Root-Daemon als Default
- dauerhafte breite `sudo`-Freigaben

## Architektur-Fazit

Das Sicherheitsmodell von `AdminBot v2` ist bewusst konservativ. Die Privilegstrategie ist finalisiert: non-root-Daemon, Service-Control primär über systemd D-Bus plus polkit, Root-Helper nur als eng begrenzte Reserveoption. Damit bleibt die lokale Macht beim AdminBot und nicht bei der externen Orchestrierung.

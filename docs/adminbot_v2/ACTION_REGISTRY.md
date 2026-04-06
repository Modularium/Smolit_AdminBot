# AdminBot v2 Action Registry

## Ziel der Action Registry

Die Action Registry ist die statische Positivliste aller vom AdminBot unterstützten Operationen. Sie ersetzt jede Form offener Shell- oder Plugin-Ausführung.

Ziele:

- kleine, harte und überprüfbare Aktionsmenge
- pro Aktion klare Eingaben, Rechte, Risiken und Rückgaben
- deterministisches Verhalten
- gute Auditierbarkeit

## Designprinzipien

- keine freie Shell
- keine generische Prozessausführung
- read-only zuerst
- mutierende Aktionen nur für klar begründete Betriebsfälle
- Dry-Run überall dort, wo semantisch sinnvoll
- kleine Parameterflächen
- idempotente Operationen bevorzugen
- privilegierte Backends nur für einzelne, explizite Aktionen

## V1-Scope-Festlegung

`v1` enthält ausschließlich:

- `system.status`
- `system.health`
- `resource.snapshot`
- `disk.usage`
- `network.interface_status`
- `service.status`
- `journal.query`
- `process.snapshot`
- `service.restart`

Nicht in `v1`:

- `service.start`
- `service.stop`

Begründung:

- `service.restart` deckt den wichtigsten operativen Eingriff ab
- `start` und `stop` vergrößern das Fehlbedienungs- und Missbrauchsrisiko, ohne für den Start der Architektur zwingend zu sein

## Risikoklassen

- `R0`: rein lesend, sehr geringe Nebenwirkung
- `R1`: lesend, aber mit begrenztem Datenschutz- oder Last-Risiko
- `R2`: mutierend, kontrollierbar und reversibel
- `R3`: mutierend, potenziell kritisch
- `R4`: systemkritisch oder zu generisch, nicht für `v1`

## Privileganforderungen

- `none`
  - keine erhöhte Privilegvermittlung nötig
- `elevated`
  - erweiterte Leserechte oder systemnahe Einsicht, aber kein mutierender privilegierter Backend-Aufruf
- `privileged-backend`
  - Aktion nutzt einen klar definierten privilegierten Backend-Pfad, in `v1` systemd D-Bus plus polkit

## Capability-Klassen für v1

- `read_basic`
- `read_sensitive`
- `service_read`
- `service_control`

## V1-Aktionsliste

## `system.status`

- Beschreibung:
  - kompakte Übersicht über Host, Kernel, Uptime, Load und Speicherzustand
- Required Capability:
  - `read_basic`
- Risk Level:
  - `R0`
- Privilege Requirement:
  - `none`
- Input Schema:
  ```json
  {
    "detail": "basic | extended"
  }
  ```
- Output Schema:
  ```json
  {
    "hostname": "string",
    "kernel": "string",
    "uptime_seconds": 0,
    "load_average": [0.0, 0.0, 0.0],
    "memory": {
      "total_bytes": 0,
      "used_bytes": 0,
      "available_bytes": 0
    }
  }
  ```
- Preconditions:
  - keine
- Side Effects:
  - keine
- Dry-Run:
  - nein
- idempotent:
  - ja

## `system.health`

- Beschreibung:
  - einfache Gesundheitsbewertung aus wenigen stabilen Checks
- Required Capability:
  - `read_basic`
- Risk Level:
  - `R0`
- Privilege Requirement:
  - `none`
- Input Schema:
  ```json
  {
    "include_checks": ["cpu", "memory", "disk_root", "swap"]
  }
  ```
- Output Schema:
  ```json
  {
    "overall_status": "ok | degraded | critical",
    "checks": [
      {
        "name": "cpu",
        "status": "ok | warning | critical",
        "current": 0.0,
        "threshold": 0.0
      }
    ],
    "warnings": ["string"]
  }
  ```
- Preconditions:
  - `include_checks` nur aus definierter Enum-Menge
- Side Effects:
  - keine
- Dry-Run:
  - nein
- idempotent:
  - ja

## `resource.snapshot`

- Beschreibung:
  - strukturierter Punkt-in-Zeit-Ressourcensnapshot
- Required Capability:
  - `read_basic`
- Risk Level:
  - `R0`
- Privilege Requirement:
  - `none`
- Input Schema:
  ```json
  {
    "include": ["cpu", "memory", "swap", "disk", "net"]
  }
  ```
- Output Schema:
  ```json
  {
    "timestamp": "RFC3339 string",
    "cpu": {},
    "memory": {},
    "swap": {},
    "disk": {},
    "net": {}
  }
  ```
- Preconditions:
  - `include` nur definierte Werte
- Side Effects:
  - keine
- Dry-Run:
  - nein
- idempotent:
  - ja

## `disk.usage`

- Beschreibung:
  - Nutzung freigegebener Dateisysteme
- Required Capability:
  - `read_basic`
- Risk Level:
  - `R0`
- Privilege Requirement:
  - `none`
- Input Schema:
  ```json
  {
    "mounts": ["/", "/var"]
  }
  ```
- Output Schema:
  ```json
  {
    "mounts": [
      {
        "path": "/",
        "total_bytes": 0,
        "used_bytes": 0,
        "available_bytes": 0,
        "percent_used": 0.0
      }
    ]
  }
  ```
- Preconditions:
  - Mountpoints müssen in der Policy-Whitelist stehen
- Side Effects:
  - keine
- Dry-Run:
  - nein
- idempotent:
  - ja

## `network.interface_status`

- Beschreibung:
  - Status und Basisdaten ausgewählter Interfaces
- Required Capability:
  - `read_basic`
- Risk Level:
  - `R0`
- Privilege Requirement:
  - `none`
- Input Schema:
  ```json
  {
    "interfaces": ["eth0", "wlan0"]
  }
  ```
- Output Schema:
  ```json
  {
    "interfaces": [
      {
        "name": "eth0",
        "state": "up | down | unknown",
        "addresses": ["string"],
        "rx_bytes": 0,
        "tx_bytes": 0
      }
    ]
  }
  ```
- Preconditions:
  - Interface-Namen müssen Pattern und Policy erfüllen
- Side Effects:
  - keine
- Dry-Run:
  - nein
- idempotent:
  - ja

## `service.status`

- Beschreibung:
  - Status einer freigegebenen Systemd-Unit
- Required Capability:
  - `service_read`
- Risk Level:
  - `R1`
- Privilege Requirement:
  - `elevated`
- Input Schema:
  ```json
  {
    "unit": "nginx.service"
  }
  ```
- Output Schema:
  ```json
  {
    "unit": "nginx.service",
    "active_state": "active | inactive | failed | activating | deactivating",
    "sub_state": "string",
    "load_state": "string",
    "unit_file_state": "string",
    "timestamp": "RFC3339 string"
  }
  ```
- Preconditions:
  - nur `.service`
  - Unit muss Policy-Regeln erfüllen
- Side Effects:
  - keine
- Dry-Run:
  - nein
- idempotent:
  - ja

## `journal.query`

- Beschreibung:
  - letzte relevante Journald-Einträge zu einer freigegebenen Unit oder Prioritätsklasse
- Required Capability:
  - `read_sensitive`
- Risk Level:
  - `R1`
- Privilege Requirement:
  - `elevated`
- Input Schema:
  ```json
  {
    "unit": "nginx.service",
    "priority_min": "warning",
    "since_seconds": 3600,
    "limit": 50
  }
  ```
- Output Schema:
  ```json
  {
    "entries": [
      {
        "timestamp": "RFC3339 string",
        "unit": "nginx.service",
        "priority": "warning",
        "message": "string"
      }
    ],
    "truncated": false
  }
  ```
- Preconditions:
  - `limit` hart begrenzt
  - `since_seconds` hart begrenzt
  - `unit` nur wenn Policy erlaubt
- Side Effects:
  - keine
- Dry-Run:
  - nein
- idempotent:
  - ja

## `process.snapshot`

- Beschreibung:
  - begrenzte Sicht auf laufende Prozesse für Diagnosezwecke
- Required Capability:
  - `read_sensitive`
- Risk Level:
  - `R1`
- Privilege Requirement:
  - `elevated`
- Input Schema:
  ```json
  {
    "top_by": "cpu | memory",
    "limit": 20
  }
  ```
- Output Schema:
  ```json
  {
    "processes": [
      {
        "pid": 123,
        "name": "string",
        "cpu_percent": 0.0,
        "memory_percent": 0.0,
        "started_at": "RFC3339 string"
      }
    ]
  }
  ```
- Preconditions:
  - `top_by` nur Enum
  - `limit` hart begrenzt
- Side Effects:
  - keine
- Dry-Run:
  - nein
- idempotent:
  - ja

## `service.restart`

- Beschreibung:
  - kontrollierter Neustart einer freigegebenen Systemd-Unit
- Required Capability:
  - `service_control`
- Risk Level:
  - `R2`
- Privilege Requirement:
  - `privileged-backend`
- Privileged Backend:
  - systemd D-Bus plus polkit
- Backend-Semantik in `v1`:
  - Interface `org.freedesktop.systemd1.Manager`
  - Methode `RestartUnit`
  - systemd-Mode nur `"replace"`
  - AdminBot-Mode nur `safe`
  - festes Mapping `safe -> RestartUnit(unit, "replace")`
  - kein `systemctl`
  - kein Shell-Fallback
  - kein alternativer Restart-Pfad
- Input Schema:
  ```json
  {
    "unit": "nginx.service",
    "mode": "safe",
    "reason": "Healthcheck failed repeatedly"
  }
  ```
- Output Schema:
  ```json
  {
    "unit": "nginx.service",
    "mode": "safe",
    "job_object_path": "/org/freedesktop/systemd1/job/1234",
    "pre_state": {
      "active_state": "active",
      "sub_state": "running"
    },
    "post_state": {
      "active_state": "active",
      "sub_state": "running"
    },
    "warnings": ["string"]
  }
  ```
- Preconditions:
  - nur `.service`
  - Unit muss in der Service-Whitelist stehen
  - `mode` in `v1` nur `safe`
  - Cooldown für wiederholte Restarts aktiv
  - Service-Control erfolgt ausschließlich über den registrierten D-Bus-Pfad
  - Dry-Run oder Preflight vor tatsächlicher Ausführung empfohlen
- Side Effects:
  - Dienstneustart
  - potenzielle kurze Unterbrechung der Verfügbarkeit
- Dry-Run:
  - ja
- idempotent:
  - nein

## Policy-Modell für die Action Registry

`v1` nutzt ein kleines TOML-Format. Beispiel:

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

[service_control]
allowed_units = ["nginx.service", "ssh.service"]
restart_cooldown_seconds = 300
max_restarts_per_hour = 3

[constraints]
default_timeout_ms = 5000
max_timeout_ms = 30000
journal_limit_max = 200
process_limit_max = 50
```

Kurze Erklärung:

- `clients.*`
  - ordnet lokale Clients oder Integrationsprozesse Capability-Mengen zu
- `actions`
  - globale Positivliste für den Daemon
- `service_control`
  - Whitelist und Cooldowns für mutierende Service-Aktionen
- `constraints`
  - allgemeine Laufzeitgrenzen

## Bewusst ausgeschlossene Aktionen

Diese Aktionen gehören ausdrücklich nicht in `v1`:

- `command.run`
- `shell.execute`
- `script.run`
- `docker.exec`
- `docker.container_control`
- `package.install`
- `package.remove`
- `package.upgrade`
- `network.reconfigure`
- `user.add`
- `user.modify`
- `file.write_arbitrary`
- `file.read_arbitrary`
- `reboot`
- `shutdown`

Grund:

- zu breiter Wirkraum
- schlechte Auditierbarkeit
- hohe Eskalations- und Fehlbedienungsgefahr

## V2/V3-Kandidaten

Mögliche spätere Kandidaten:

- `service.start`
- `service.stop`
- `diagnostics.collect_bundle`
- `package.update_index`
- `package.upgrade_safe`

Voraussetzungen:

- reife Policy
- Freigabe- und Cooldown-Mechanismen
- ausgereifte Precondition- und Impact-Bewertung

# AdminBot v2 Attack Surfaces

## Zweck

Dieses Dokument listet die relevanten Angriffsoberflaechen des aktuellen AdminBot-v2-Stands auf und bewertet den bereits vorhandenen Schutz.

## 1. Unix Socket IPC

### Relevanz

Der Unix Socket ist die primaere Eintrittsstelle in das System.

### Aktueller Stand

- Pfad: `/run/adminbot/adminbot.sock`
- Modus: `0660`
- Gruppe: `adminbotctl`
- Peer-Credentials werden gelesen
- der Daemon verarbeitet eingehende Verbindungen sequentiell

### Angriffsmoeglichkeiten

- unberechtigter Socket-Zugriff bei falscher Gruppenvergabe
- Socket-Flooding durch viele Verbindungen
- Slow-Client blockiert den Daemon, weil keine Verbindungs-Timeouts existieren
- uebergrosse Frames fuehren zu ungebremsten Allokationen

### Bestehender Schutz

- lokale Transportgrenze
- Dateirechte
- `SO_PEERCRED`

### Restrisiko

- hoch fuer lokale Verfuegbarkeit

## 2. Framing und JSON-Parsing

### Relevanz

Length-prefixed JSON ist robust, aber nur solange die Laenge selbst begrenzt wird.

### Aktueller Stand

- 4-Byte big-endian Laengenprefix
- Payload wird direkt in einen `Vec<u8>` der angegebenen Groesse gelesen
- `serde` mit `deny_unknown_fields` fuer zentrale Typen

### Angriffsmoeglichkeiten

- DoS durch sehr grosse Payloads
- CPU- und Speicherverbrauch durch haeufige fehlerhafte Requests
- Audit-Spam durch systematisch invalide Requests

### Bestehender Schutz

- strukturierte Deserialisierung
- unbekannte Felder und unbekannte Enum-Werte werden abgewiesen

### Restrisiko

- hoch fuer Speicher- und Verfuegbarkeitsaspekte, weil keine globale Payload-Grenze existiert

## 3. Request-Metadaten

### Relevanz

`requested_by`, `request_id` und andere Metadaten beeinflussen Audit und teilweise Policy-Entscheidungen.

### Aktueller Stand

- `request_id` muss UUID sein
- `requested_by.type` und `requested_by.id` kommen direkt vom Client
- Policy kann `allowed_request_types` auswerten

### Angriffsmoeglichkeiten

- Spoofing von `requested_by.type`
- Spoofing von `requested_by.id`
- Replay alter Requests mit neuem oder wiederverwendetem `request_id`

### Bestehender Schutz

- Peer-Credentials werden separat gelesen
- Audit loggt echte Peer-UID/GID/PID

### Restrisiko

- mittel bis hoch, weil Metadaten nicht an die echte Prozessidentitaet gebunden werden

## 4. Action Registry

### Relevanz

Die Registry ist die Positivliste aller Funktionen.

### Aktueller Stand

- statisch im Binary
- unbekannte Actions werden vor Ausfuehrung verworfen
- Parameter werden action-spezifisch deserialisiert

### Angriffsmoeglichkeiten

- falsche Action-Namen
- semantische Grenzfaelle innerhalb erlaubter Actions

### Bestehender Schutz

- keine dynamische Registry
- keine generische Shell- oder Command-Exec-Schnittstelle

### Restrisiko

- niedrig bis mittel

## 5. Policy Engine

### Relevanz

Die Policy ist die fachliche Zugriffsgrenze.

### Aktueller Stand

- TOML mit `deny_unknown_fields`
- Version muss `1` sein
- Clients koennen ueber `unix_user` und `unix_group` gemappt werden
- Capabilities, Unit-Whitelist, Mount-Whitelist, Limits und Cooldowns sind vorhanden

### Angriffsmoeglichkeiten

- Policy-Datei manipulieren
- Fehlkonfiguration durch zu breite Capabilities
- Umgehung durch gleiche Unix-Identitaet mit unterschiedlichem `requested_by.type`

### Bestehender Schutz

- striktes Parsing
- keine freien Policy-Ausdruecke
- Capability-Pruefung ist zentral

### Restrisiko

- mittel, technisch solide, aber stark von sicherem Deployment abhaengig

## 6. Filesystem-Zugriffe

### Relevanz

Read-only Actions lesen aus `/proc`, `/sys`, Netzwerkschnittstellen und Mount-Informationen.

### Aktueller Stand

- `disk.usage` nutzt Mount-Whitelist
- Prozess- und Systemstatus lesen direkt aus Kernel-/Userspace-Dateien

### Angriffsmoeglichkeiten

- Information Disclosure ueber legitime Read-Actions
- tauschbare oder manipulierte lokale Dateien ausserhalb von Kernel-Interfaces

### Bestehender Schutz

- statische Action-Auswahl
- Param-Validierung
- Mount-Whitelist

### Restrisiko

- mittel, weil Read-Only nicht automatisch harmlos ist

## 7. systemd D-Bus

### Relevanz

`service.restart` ist die kritischste mutierende Action.

### Aktueller Stand

- nur `RestartUnit(unit, "replace")`
- Unit-Name muss `.service` sein und nur ASCII-Zeichen aus einer kleinen Menge enthalten
- Whitelist, Cooldown und Rate-Limit werden lokal geprueft
- Pre- und Post-Status werden erfasst

### Angriffsmoeglichkeiten

- Neustart nicht freigegebener Units
- Ausnutzung zu breiter polkit-Regeln
- D-Bus-Backend-Ausfall als Verfuegbarkeitsproblem

### Bestehender Schutz

- keine Shell
- keine alternativen Restart-Pfade
- keine freien systemd-Methoden

### Restrisiko

- mittel, stark abhaengig von polkit und Betriebsdisziplin

## 8. journald-Integration

### Relevanz

Journald ist sowohl Lesepfad als auch Audit-Sink.

### Aktueller Stand

- `journal.query` filtert optional auf `_SYSTEMD_UNIT`
- Limit und Zeitfenster werden geprueft
- Audit schreibt strukturierte Felder

### Angriffsmoeglichkeiten

- sensitive data leaks in Journal-Nachrichten
- Log-Injection auf Inhaltsebene durch fremde Prozesse, deren Logs spaeter gelesen werden
- Audit-Ausfall bei fehlendem journald

### Bestehender Schutz

- Unit-Whitelist fuer Journal-Abfragen
- fallback JSON ueber stderr

### Restrisiko

- mittel, besonders fuer Vertraulichkeit

## 9. systemd Service Hardening

### Relevanz

Die Service-Unit reduziert die Folgen eines Prozesskompromisses.

### Aktueller Stand

- `User=adminbot`
- `NoNewPrivileges=true`
- `PrivateTmp=true`
- `PrivateDevices=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- `MemoryDenyWriteExecute=true`
- `RestrictRealtime=true`
- `LockPersonality=true`
- `CapabilityBoundingSet=`
- `RestrictAddressFamilies=AF_UNIX`

### Angriffsmoeglichkeiten

- Prozesskompromiss innerhalb des Daemons
- Missbrauch lokaler Dateipfade und Backends

### Bestehender Schutz

- gute non-root-Baseline
- reduzierte Netzwerkfaehigkeiten

### Restrisiko

- mittel, weil weitere systemd-Haertungsoptionen noch offen sind

## 10. Externe Betriebsartefakte

### Relevanz

Nicht alles Kritische liegt im Rust-Code.

### Beispiele

- polkit-Regeln
- Dateirechte fuer `/etc/adminbot/policy.toml`
- Unit-Installation
- Mitgliedschaft in `adminbotctl`

### Restrisiko

- hoch, wenn Deployment- und Betriebsartefakte nicht dieselbe Sorgfalt wie der Core-Code erhalten

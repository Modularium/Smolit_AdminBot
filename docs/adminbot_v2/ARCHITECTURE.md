# AdminBot v2 Architektur

## Zielbild

`AdminBot v2` ist ein nativer, hochsicherer Linux-Systemdienst in Rust. Er ist kein AI-System, kein Agenten-Framework und kein generischer Automationsbaukasten. Seine Aufgabe ist eng begrenzt:

- lokale Systemzustände strukturiert erfassen
- kleine, klar definierte Admin-Aktionen sicher ausführen
- jede sicherheitsrelevante Anfrage deterministisch prüfen, protokollieren und beantworten

`Agent-NN` übernimmt künftig die Denk-, Planungs- und Orchestrierungsschicht. `AdminBot` bleibt der lokale Executor mit harter Policy-Grenze.

## Leitprinzipien

- Sicherheit vor Funktionsfülle
- deterministische Aktionen statt freier Shell
- kleine, typisierte Schnittstellen statt generischer Plugins
- non-root als Default
- Privilegien aktionsbezogen, nicht prozessweit
- niedriger Footprint für Raspberry Pi und ältere Hardware
- vollständige Auditierbarkeit jeder Aktion
- lokale Vertrauensgrenze bleibt beim AdminBot, nicht bei `Agent-NN`

## Architektur-Festlegungen

### Root- und Privilegmodell

- `adminbotd` läuft standardmäßig nicht als Root.
- Root ist Eigenschaft einzelner Aktionen, nicht des gesamten Daemons.
- Es gibt keine generische Shell, kein `exec`, keinen `sudo`-Wrapper und kein Plugin-System im Core.
- Jede Aktion ist registriert, validiert, policy-geprüft und auditiert.

### Entscheidung Service Control für `service.restart`

Für `v1` wird folgende Strategie verbindlich festgelegt:

- Primary: systemd D-Bus plus polkit
- Fallback: kein automatischer Fallback in `v1`
- Reserveoption für spätere Eskalation: dedizierter Root-Helper nur bei nachgewiesenem Bedarf
- Verworfen für `v1`: Linux Capabilities als primärer Weg für Service-Control

#### Vergleich der Optionen

##### Option A: systemd D-Bus plus polkit

Sicherheit:

- stark, weil die Privilegentscheidung auf der dafür vorgesehenen Systemebene bleibt
- kein generischer Root-Prozess im AdminBot
- Aktion bleibt semantisch auf Service-Management begrenzt

Komplexität:

- moderat
- D-Bus- und polkit-Integration ist nicht trivial, aber fachlich sauber

Wartbarkeit:

- gut
- nutzt Linux-Standardmechanismen statt Eigenkonstruktionen

Kontrolle und Auditierbarkeit:

- gut
- AdminBot kann Request, Policy, D-Bus-Aufruf und Ergebnis auditieren
- Journald/systemd bleiben systemnaher Referenzpunkt

Kompatibilität mit Zielarchitektur:

- sehr gut
- passt zum non-root-Daemon und zur aktionsbezogenen Privilegstrategie

##### Option B: dedizierter Root-Helper

Sicherheit:

- nur akzeptabel, wenn extrem eng geschnitten
- birgt das Risiko, dass aus einem kleinen Helper schleichend ein generischer Privilegpfad wird

Komplexität:

- höher als zunächst sichtbar
- eigener IPC-Vertrag, eigene Härtung, eigene Auditkette

Wartbarkeit:

- schlechter als Option A
- zusätzlicher privilegierter Codepfad muss dauerhaft gepflegt werden

Kontrolle und Auditierbarkeit:

- kontrollierbar, aber nur mit viel Disziplin
- gesamte Privileggrenze läge im eigenen Code

Kompatibilität mit Zielarchitektur:

- nur als Reserveoption vertretbar

##### Option C: Linux Capabilities

Sicherheit:

- für Service-Control ungeeignet als Primärmodell
- `systemctl restart` oder äquivalente Unit-Steuerung lässt sich nicht sauber auf wenige Kernel-Capabilities reduzieren

Komplexität:

- scheinbar niedrig, praktisch aber unsauber

Wartbarkeit:

- schwach
- schwer nachvollziehbar, warum bestimmte Capabilities ausreichen oder nicht

Kontrolle und Auditierbarkeit:

- schlechter als D-Bus/polkit
- kein sauberer fachlicher Gatekeeper für einzelne Unit-Operationen

Kompatibilität mit Zielarchitektur:

- unpassend

#### Ergebnis

`service.restart` wird in `v1` primär über systemd D-Bus plus polkit umgesetzt. Das passt am besten zur festgelegten Architektur:

- non-root-Daemon
- aktionsbezogene Privilegien
- keine generische Root-Komponente im Normalfall
- klare Semantik und gute Systemintegration

Ein dedizierter Root-Helper wird nicht Teil von `v1`, aber als klar begrenzte Reserveoption für spätere Phasen dokumentiert, falls bestimmte Zielsysteme oder Betriebsumgebungen D-Bus/polkit unzureichend bereitstellen.

#### Verbindliche v1-Implementierungssemantik

Für `service.restart` gilt in `v1` verbindlich:

- D-Bus-Interface: `org.freedesktop.systemd1.Manager`
- D-Bus-Methode: `RestartUnit`
- erlaubter systemd-Mode: nur `"replace"`
- erlaubter AdminBot-Mode: nur `"safe"`
- festes Mapping:
  - `safe -> RestartUnit(unit, "replace")`

Explizit nicht Teil von `v1`:

- kein Aufruf von `systemctl`
- kein Shell-Fallback
- kein alternativer Restart-Pfad
- kein komplexes asynchrones Job-Framework

Semantik:

- der IPC-Request bleibt synchron
- der D-Bus-Aufruf liefert einen systemd-Job-Object-Path
- `adminbotd` führt danach einen kleinen, kontrollierten Post-Check aus
- die Response enthält strukturiert Unit, Modus, Job-Object-Path, Pre-State, Post-Check-Ergebnis sowie Warnings oder Fehler

Begründung:

- diese Variante hält `v1` klein und deterministisch
- sie vermeidet einen zweiten operativen Pfad neben D-Bus/polkit
- sie reduziert Implementierungs- und Testaufwand gegenüber mehreren Restart-Modi oder eigenem Job-Handling
- sie erzwingt eine klar auditierbare Semantik ohne versteckte Shell- oder `systemctl`-Abhängigkeiten

## Komponentenmodell

## 1. `adminbotd`

Der Hauptprozess des Systems.

Aufgaben:

- startet alle internen Subsysteme
- bindet den lokalen Unix Domain Socket
- lädt Konfiguration und Policy
- nimmt Requests entgegen und steuert den Ablauf

Abhängigkeiten:

- Config Loader
- IPC Server
- Policy Engine
- Action Registry
- Audit Logger
- Runtime Context

Sicherheitsrelevanz:

- zentrale Vertrauensinstanz
- darf keine generische Shell-API anbieten
- darf keine Planungslogik oder LLM-Logik enthalten

v1:

- ja

später oder nie:

- kein eingebautes Plugin-System im Core
- keine verteilte Steuerung

## 2. IPC Server

Lokaler Request/Response-Server auf Basis eines Unix Domain Socket.

Aufgaben:

- Requests entgegennehmen
- Peer-Credentials und Socket-Rechte prüfen
- Nachrichten validieren
- Responses strukturiert zurückgeben

Abhängigkeiten:

- `adminbotd`
- Request Validator
- Audit Logger

Sicherheitsrelevanz:

- erste technische Sicherheitsgrenze
- erzwingt lokale Nutzung und typisierte Aufrufe

v1:

- ja

später:

- optional read-only HTTP-Bridge auf `localhost`, nicht Teil des Grundmodells

## 3. Action Registry

Statische, im Binary bekannte Liste erlaubter Aktionen.

Aufgaben:

- registriert alle unterstützten Actions
- beschreibt Parameter, Capability, Risiko, Privilegstufe und Handler
- verhindert offene Funktionsausweitung

Abhängigkeiten:

- Policy Engine
- Executor

Sicherheitsrelevanz:

- zentrale Positivliste
- ersetzt jede Form freier Shell-Ausführung

v1:

- ja

später:

- Erweiterung nur über kontrollierte Releases

## 4. Policy Engine

Entscheidet lokal, ob eine Aktion ausgeführt werden darf.

Aufgaben:

- validiert Aktion gegen Policy und Capability-Anforderung
- prüft Herkunft, Privilegstufe, Cooldowns, Limits, Precondition und Risikoklasse
- kann Aktionen ablehnen, nur als Dry-Run erlauben oder wegen Cooldown sperren

Abhängigkeiten:

- Config Loader
- Runtime Context
- Action Registry

Sicherheitsrelevanz:

- zweite fachliche Sicherheitsgrenze
- lokale Autorität gegenüber Mensch, CLI und `Agent-NN`

v1:

- ja

später:

- feinere Rollen- oder Mandantenmodelle

## 5. Capability-/Authorization-Layer

Kleine, harte Autorisierungsschicht innerhalb der Policy Engine.

Aufgaben:

- mappt Request-Herkunft auf Capability-Mengen
- trennt read-only, elevated-read und privileged-backend-actions
- unterscheidet menschliche und maschinelle Anfragen

Abhängigkeiten:

- Peer-Credential-Daten
- Policy-Datei

Sicherheitsrelevanz:

- verhindert, dass `Agent-NN` dieselbe Macht wie ein lokaler Operator erhält

v1:

- ja

## 6. Request Validator

Schema- und Semantikvalidierung für Requests und Action-Parameter.

Aufgaben:

- Datentypen prüfen
- Wertebereiche, Enumerationen, Längenlimits und Identifier-Regeln prüfen
- unsinnige oder unsichere Parameter vor Ausführung blockieren

Abhängigkeiten:

- IPC Server
- Action Registry

Sicherheitsrelevanz:

- reduziert Missbrauchsfläche massiv

v1:

- ja

## 7. Executor

Kleiner Ausführungskern für registrierte Aktionen.

Aufgaben:

- ruft ausschließlich vordefinierte Handler auf
- kapselt journald-, procfs-, sysfs-, netlink- oder systemd-nahe Operationen
- trennt read-only und mutierende Aktionen

Abhängigkeiten:

- Action Registry
- Policy Engine
- Backend Adapter

Sicherheitsrelevanz:

- darf keine allgemeine Prozess- oder Shell-API darstellen

v1:

- ja

Spezifisch für `service.restart` in `v1`:

- der Executor ruft ausschließlich `org.freedesktop.systemd1.Manager.RestartUnit(unit, "replace")` auf
- danach erfolgt nur ein kleiner synchroner Post-Check
- kein eigenes Job-Scheduling, keine Hintergrund-Queue und kein alternativer Backend-Pfad

## 8. Privileged Backend Adapter

Schmale interne Abstraktionsschicht für Aktionen, die auf privilegierte Systemmechanismen zugreifen.

Aufgaben:

- bindet Service-Control über systemd D-Bus und polkit an
- kapselt später optional alternative Backends ohne IPC-Vertrag zu ändern

Backends in `v1`:

- systemd D-Bus plus polkit für `service.restart`

Reserve-Backends später:

- dedizierter Helper nur falls nachgewiesen nötig

Sicherheitsrelevanz:

- hält Privileglogik aus dem generischen Executor heraus

v1:

- ja

## 9. Privileged Helper

Nicht Teil des Standardpfads in `v1`, aber als Minimalreserve dokumentiert.

Nur falls später benötigt, gilt:

- Verantwortungsbereich ausschließlich Service-Control
- keine Shell
- keine freien Strings außer validiertem Unit-Namen aus Policy
- keine Dateipfade
- keine Subcommands
- nur strukturierte Requests wie `restart_unit`

Kommunikationsmodell:

- nur lokaler, interner Kanal zwischen `adminbotd` und Helper
- nicht direkt für CLI oder `Agent-NN`

Minimalrechte:

- ausschließlich Neustart freigegebener Systemd-Units
- keine allgemeine Prozesssteuerung
- keine Benutzer-, Paket- oder Dateisystemverwaltung

## 10. Audit Logger

Append-only Audit-Schicht für alle Requests und sicherheitsrelevanten Entscheidungen.

Aufgaben:

- Request-Annahme loggen
- Policy-Entscheidungen loggen
- Precondition-, Dry-Run- und Execution-Ergebnisse loggen
- Audit-Referenzen erzeugen

Abhängigkeiten:

- journald
- optional lokaler Audit-Pfad

Sicherheitsrelevanz:

- Kernbaustein für Nachvollziehbarkeit und Incident Analysis

v1:

- ja

## 11. Runtime Context / State

Kleiner, flüchtiger Laufzeitkontext für Korrelation, Rate-Limits und Cooldowns.

Aufgaben:

- Request-Korrelation
- Rate-Limit-Zustand
- Cooldowns für mutierende Aktionen
- Health-Status
- letzte erfolgreiche bzw. fehlgeschlagene Aktionen

Abhängigkeiten:

- `adminbotd`
- Audit Logger

Sicherheitsrelevanz:

- kein Workflow-Speicher
- keine Agenten-Memory-Funktion

v1:

- ja, minimal

## 12. Health / Watchdog

Eigenüberwachung des Daemons.

Aufgaben:

- Liveness und Readiness
- begrenzte Selbstdiagnose
- saubere Zusammenarbeit mit systemd Restart-Strategien

Abhängigkeiten:

- systemd

Sicherheitsrelevanz:

- verhindert stille Ausfälle

v1:

- ja, klein

## 13. Config Loader

Lädt statische Konfiguration und Policy aus kleinen, versionierten Formaten.

Aufgaben:

- Pfade, Limits, Socket-Modell, Logging und Backend-Optionen laden
- Konfigurationsfehler früh hart ablehnen

Abhängigkeiten:

- `adminbotd`

Sicherheitsrelevanz:

- Konfiguration darf nicht zu generischer Skriptausführung führen

v1:

- ja

## Betriebsmodell

`AdminBot v2` läuft als nativer Linux-Systemdienst unter `systemd`.

### Prozessmodell

- genau ein primärer Daemon: `adminbotd`
- keine dauerhaften Nebenprozesse für LLM, ML, Web-UI oder Observability-Stacks
- kein privilegierter Root-Hintergrundprozess im Normalfall

### Nutzer- und Gruppenmodell

- Systembenutzer: `adminbot`
- Systemgruppe: `adminbot`
- optionale Client-Gruppe: `adminbotctl`

Grundidee:

- der Dienst läuft nicht als Root
- read-only und Kontrollaktionen werden möglichst systemnah und nicht über Root-Prozessprivilegien gelöst
- aktionsbezogene Eskalation erfolgt über systemd D-Bus plus polkit
- polkit ist in `v1` nur die schmale System-Privilegbrücke für den eng definierten Service-Control-Pfad
- die fachliche Entscheidung bleibt immer in `adminbotd` bei Policy, Capability, Whitelist und Cooldown

### Lokale Pfade

- Konfiguration: `/etc/adminbot/adminbot.toml`
- Policy: `/etc/adminbot/policy.toml`
- Socket: `/run/adminbot/adminbot.sock`
- Runtime-State: `/run/adminbot/`
- persistenter State: `/var/lib/adminbot/`
- optionale Audit-Dateien: `/var/log/adminbot/audit/`

### Logging

- primär journald
- zusätzlich optionale JSONL-Auditdateien
- keine ELK-, Prometheus- oder Grafana-Pflicht im Core

### Update- und Deploy-Idee

- signierte oder anderweitig verifizierte Paketierung
- kein Auto-Update im Daemon
- keine Laufzeitdownloads externer Modelle, Skripte oder Konfigurationen

## systemd Hardening im Betriebsmodell

Als realistische Basishärtung für `v1`:

- `NoNewPrivileges=true`
- `PrivateTmp=true`
- `PrivateDevices=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- `MemoryDenyWriteExecute=true`
- `RestrictRealtime=true`
- `LockPersonality=true`
- `CapabilityBoundingSet=` möglichst leer
- `RestrictAddressFamilies=AF_UNIX` als Zielwert
- systemd D-Bus und polkit werden explizit gegen `RestrictAddressFamilies=AF_UNIX` verifiziert
- Erweiterungen über `AF_UNIX` hinaus sind nur minimal, dokumentiert und technisch begründet zulässig
- `MemoryMax=` konservativ
- `CPUQuota=` konservativ

## Rust-Repo-Struktur für die Implementierungsphase

Empfohlene Grundstruktur:

```text
src/
  main.rs
  daemon/
    mod.rs
    service.rs
    runtime.rs
  ipc/
    mod.rs
    server.rs
    framing.rs
    protocol.rs
    peer.rs
  actions/
    mod.rs
    registry.rs
    schemas.rs
    system_status.rs
    system_health.rs
    resource_snapshot.rs
    disk_usage.rs
    network_interface_status.rs
    service_status.rs
    service_restart.rs
    journal_query.rs
    process_snapshot.rs
  policy/
    mod.rs
    model.rs
    loader.rs
    evaluator.rs
    cooldowns.rs
  audit/
    mod.rs
    logger.rs
    event.rs
  system/
    mod.rs
    systemd.rs
    journald.rs
    procfs.rs
    network.rs
  backends/
    mod.rs
    service_control.rs
    systemd_dbus.rs
    helper_iface.rs
  config/
    mod.rs
    settings.rs
  error/
    mod.rs
    codes.rs
```

Ziel der Struktur:

- klare Trennung von Control Plane, Actions, Policy, Audit und Systemzugriff
- privilegierte Backends nur als schmale Adapter, nicht als zweite Architektur
- keine Vermischung von IPC und Business-Logik

## V1-Inhalt

`AdminBot v1` soll enthalten:

- `adminbotd`
- Unix Domain Socket IPC
- JSON-basierter, length-prefixed Request/Response-Vertrag
- kleine Action Registry
- Request Validator
- Policy-/Capability-Layer
- Audit Logger
- systemd-/journald-Integration
- Service-Control über systemd D-Bus plus polkit für `service.restart`

## Nicht-Ziele

Folgendes gehört ausdrücklich nicht in `AdminBot v1`:

- ML/LLM
- Modell-Downloads
- freie Shell-Ausführung
- generische `run command`-API
- generische Root-Helper für beliebige Aktionen
- Docker-Management als Core-Funktion
- generisches Plugin-System
- Web-UI
- ELK-, Grafana- oder Prometheus-Core
- verteilte Multi-Agent-Logik
- komplexe Workflow-Engine
- selbstlernende oder adaptive Automatik

## Bewusst verworfene Altideen aus Smolit_AdminBot

- Python als Betriebs- und Sicherheitskern
- lokales Transformer-Modell im Admin-Prozess
- ML-basierte Anomalieerkennung im Core
- Shell-Skripte als primäres Service- und Kontrollmodell
- konkurrierende Supervisor-, systemd-, Docker- und Shell-Primärpfade
- Docker-Socket-Zugriff als Standardfähigkeit

## Architektur-Fazit

`AdminBot v2` bleibt bewusst klein, lokal und hart begrenzt. Die Root-Strategie ist final: `adminbotd` bleibt non-root, Privilegien werden aktionsbezogen über systemd D-Bus plus polkit vermittelt, und ein Root-Helper ist nur Reserveoption statt Grundpfeiler. Damit ist die Architektur für eine konservative `v1`-Implementierung ausreichend konkret und mit dem Zielbild konsistent.

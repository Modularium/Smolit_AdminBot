# AdminBot v2 Security Review v1

## Executive Summary

AdminBot v2 ist sicherheitsarchitektonisch deutlich staerker als typische lokale Automationsdienste:

- non-root Daemon
- statische Action Registry
- keine freie Shell
- lokale Unix-Socket-IPC
- D-Bus plus polkit statt generischem Root-Exec
- strukturierte Auditierung

Der Ist-Zustand ist aus Security-Sicht jedoch noch nicht uneingeschraenkt production-ready. Der wichtigste Grund ist nicht klassische Remote-Code-Execution, sondern eine Kombination aus:

- schwacher Verfuegbarkeitsabsicherung gegen lokale DoS-Angriffe
- zu loser Bindung zwischen Request-Metadaten und echter Client-Identitaet
- starker Abhaengigkeit von korrektem Deployment fuer Policy- und polkit-Sicherheit

## Bewertungslegende

- `gut`: solide umgesetzt und architekturkonform
- `akzeptabel`: brauchbar, aber mit klaren offenen Risiken
- `kritisch`: relevantes Sicherheitsrisiko oder unzureichende Schutzwirkung

## 1. Architektur-Sicherheit

### Bewertung

- `gut`

### Begruendung

- keine freie Shell
- keine Plugins
- kein LLM im Core
- non-root als Grundmodell
- Privilegien sind aktionsbezogen statt prozessweit

### Konkrete Risiken

- Sicherheitswirkung haengt stark von korrektem Deployment ausserhalb des Repo ab
- einige Schutzversprechen aus der Policy sind bereits modelliert, aber nicht vollstaendig technisch erzwungen

## 2. IPC-Design

### Bewertung

- `akzeptabel`

### Begruendung

- Unix Socket statt Netzwerkschnittstelle
- `SO_PEERCRED` vorhanden
- versionierte Requests
- `deny_unknown_fields` verhindert stilles Param-Driften

### Konkrete Risiken

- keine maximale Frame-Groesse
- keine Socket-Timeouts
- sequentielle Verarbeitung erhoeht DoS-Anfaelligkeit
- `requested_by.type` und `requested_by.id` sind selbstdeklarierte Metadaten

## 3. Policy-System

### Bewertung

- `akzeptabel`

### Begruendung

- klares TOML-Schema
- Capability-Modell
- Whitelist fuer Actions, Mounts und Service-Units
- Cooldown und Rate-Limit fuer `service.restart`

### Konkrete Risiken

- Dateirechte und Integritaet der Policy-Datei werden nicht geprueft
- `allowed_request_types` kann durch ungebundene Request-Metadaten anfaellig sein
- `max_parallel_mutations` ist modelliert, aber derzeit nicht aktiv erzwungen

## 4. Action-System

### Bewertung

- `gut`

### Begruendung

- feste Registry
- explizite Handler
- action-spezifische Param-Validierung
- Unit- und Interface-Namen werden eingeschraenkt

### Konkrete Risiken

- Read-only Actions koennen trotzdem sensible Daten offenlegen
- einige Limits sind punktuell, aber nicht global

## 5. systemd-Integration

### Bewertung

- `gut`

### Begruendung

- `service.restart` nutzt nur `RestartUnit(unit, "replace")`
- kein `systemctl`
- kein Shell-Fallback
- Unit-Whitelist, Precondition-Check, Cooldown und Rate-Limit vorhanden

### Konkrete Risiken

- polkit-Regeln sind ein externer kritischer Sicherheitsfaktor
- Backend-Fehler fuehren zu Verfuegbarkeitsproblemen
- Rate-Limits sind nicht persistent ueber Daemon-Neustarts

## 6. Logging und Audit

### Bewertung

- `akzeptabel`

### Begruendung

- Request-Lifecycle wird protokolliert
- Peer UID/GID/PID werden erfasst
- Policy- und Capability-Entscheidungen sind sichtbar
- strukturierte journald-Felder sind vorhanden

### Konkrete Risiken

- Fallback auf stderr ist weniger robust als ein dedizierter Audit-Sink
- Audit- und Journaldaten enthalten potentiell sensible Inhalte
- keine Absicherung gegen Audit-Flooding durch invalide Requests

## 7. systemd Hardening

### Bewertung

- `akzeptabel`

### Begruendung

- gute Baseline ist vorhanden:
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
- live validiert mit `systemd-analyze security`

### Konkrete Risiken

- weitere sinnvolle Hardening-Optionen fehlen noch
- `systemd-analyze security` zeigt weiterhin offene Härtungspunkte
- die Sicherheitsnote `4.7 OK` ist brauchbar, aber kein Ersatz fuer eine minimalistische Attack-Surface-Reduktion

## Gesamturteil

### Staerken

- klare Sicherheitsarchitektur
- kleine, deterministische Schnittstelle
- keine versteckten Privilegpfade
- gute D-Bus- und Audit-Semantik

### Schwaechen

- lokale DoS-Widerstandskraft ist zu schwach
- Client-Metadaten sind nicht stark genug an Peer-Identitaet gebunden
- Betriebsartefakte ausserhalb des Repo sind sicherheitskritisch

## Top 10 Risiken

1. Keine globale Begrenzung der IPC-Frame-Groesse
2. Keine Socket-Timeouts, dadurch Slow-Client-DoS moeglich
3. Sequentielle Verbindungsverarbeitung erhoeht Verfuegbarkeitsrisiko
4. `requested_by.type` ist selbstdeklarativ und kann Security-Semantik beeinflussen
5. Policy-Dateirechte und Integritaet werden nicht im Code verifiziert
6. polkit-Konfiguration ist externer Single Point of Failure fuer privilegierte Aktionen
7. `journal.query` kann sensitive Inhalte aus systemnahen Logs offenlegen
8. Cooldown- und Rate-Limit-Zustaende sind nicht persistent
9. `max_parallel_mutations` ist modelliert, aber nicht aktiv erzwungen
10. Audit-Fallback auf stderr ist im Stoerungsfall schwächer als ein robuster Zweitsink

## Top 10 empfohlene Verbesserungen

1. Harte Obergrenze fuer IPC-Frame-Groessen definieren und spaeter technisch erzwingen
2. Read-/Write-Timeouts fuer Socket-Verbindungen einfuehren
3. Admission-Control oder einfache lokale Rate-Limits pro Peer ergaenzen
4. `requested_by` staerker an echte lokale Identitaet binden
5. Policy-Dateirechte und Eigentuemer beim Start validieren
6. polkit-Regeln versionieren und als Security-Artefakt reviewen
7. Redaktionsstrategie fuer `journal.query` und Audit-Daten definieren
8. Persistente oder betrieblich sichtbare Restart-Abuse-Erkennung einplanen
9. `max_parallel_mutations` vor jeder spaeteren Parallelisierung aktiv erzwingen
10. Hardening-Unit weiter in Richtung reduzierter Kernel-, Proc- und Syscall-Angriffsoberflaeche entwickeln

## Production-Readiness-Urteil

### Urteil

- `nicht uneingeschraenkt production-ready`

### Einordnung

Fuer eine kontrollierte, lokal administrierte Umgebung mit sauberem Deployment, enger polkit-Konfiguration und konservativer Client-Zuordnung ist der Stand bereits brauchbar.

Fuer eine allgemein robuste produktive Freigabe gegen lokale Fehlkonfiguration, kompromittierte Prozesse und Verfuegbarkeitsangriffe fehlen jedoch noch zentrale Härtungen und Betriebs-Guardrails.

# AdminBot Security Fix Roadmap v1.0.x

## Executive Summary

AdminBot v1 verfuegt bereits ueber eine starke Sicherheitsarchitektur:

- non-root Daemon
- statische Action Registry
- kein Shell-Exec
- keine Plugins
- lokale Unix-Socket-IPC
- systemd D-Bus plus polkit statt Root-Fallback
- strukturierte Policy- und Audit-Pfade

Die vorhandene Review zeigt aber klar, dass der aktuelle Stand noch nicht als "hoch sicher fuer produktiven Einsatz" gelten darf. Die groessten Luecken liegen nicht in Remote-RCE, sondern in:

- Verfuegbarkeit und DoS-Haertung an der IPC-Grenze
- zu loser Bindung zwischen Request-Metadaten und echter Peer-Identitaet
- starker Abhaengigkeit von korrekt deployten Policy-, polkit- und Service-Artefakten
- modellierten, aber noch nicht technisch erzwungenen Sicherheitsmechanismen

Ziel dieser Roadmap ist kein Minimal-Patchset, sondern eine systematische Nachhaertung von AdminBot v1.0.x auf ein praktisch maximal robustes Sicherheitsniveau ohne chaotische Architekturbrueche.

## Zielbild

AdminBot soll fuer lokale Systemadministration so sicher wie praktisch sinnvoll gehaertet werden.

Das bedeutet konkret:

- Input-Grenzen sind hart und technisch erzwungen.
- Sicherheitsrelevante Identitaetsentscheidungen basieren nicht auf selbstdeklarativen Request-Feldern.
- Betriebsartefakte wie Policy, polkit und systemd-Units werden als Security-Artefakte behandelt.
- Missbrauch durch Flooding, langsame Clients und wiederholte mutierende Requests wird aktiv begrenzt.
- Read-only-Funktionen und Audit-Pfade werden auf Informationsabfluss und Betriebsrobustheit geprueft.
- Release- und Deployment-Prozesse enthalten explizite Security-Gates.

## Prioritaetsmodell

### P0

Kritisch. Muss vor einer echten produktiven Freigabe mit hohem Sicherheitsanspruch erledigt werden.

### P1

Hoch. Sollte in v1.0.x zeitnah nachgezogen werden, um das Zielbild belastbar zu machen.

### P2

Mittel. Sinnvolle Nachhaertung nach den Kernblockern.

### P3

Spaeter oder Defense in Depth. Gute Verbesserungen, aber keine unmittelbaren Blocker.

## Security-Arbeitsphasen

### Phase A: P0 IPC / DoS / Input-Boundary Hardening

Ziel:

- harte technische Begrenzung der IPC-Angriffsoberflaeche
- Schutz gegen Speicher-, Timing- und Flooding-Missbrauch

Enthaelt:

- `#71` Enforce maximum IPC frame size
- `#72` Add IPC socket read timeout
- `#73` Add IPC socket write timeout
- `#74` Add local admission control for IPC flooding

Abhaengigkeiten:

- keine vorgeschalteten Security-Phasen

### Phase B: P0/P1 Identity / AuthZ / Policy Binding

Ziel:

- Security-Entscheidungen an reale Peer-Identitaet koppeln
- modellierte Controls technisch erzwingen

Enthaelt:

- `#75` Bind request metadata to peer credentials for security decisions
- `#78` Enforce max_parallel_mutations at runtime
- `#83` Add mutating request replay and idempotency strategy
- `#84` Persist restart abuse counters across daemon restarts

Abhaengigkeiten:

- Phase A sollte zuerst abgeschlossen sein, weil Admission-Control und Timeouts die Missbrauchsbasis senken

### Phase C: P0/P1 Deployment / polkit / Betriebsartefakte

Ziel:

- Security-kritische Deploy-Artefakte als Teil des Systems behandeln statt als unkontrollierte Umgebungsvoraussetzung

Enthaelt:

- `#76` Validate policy file owner and mode at startup
- `#77` Version and document polkit rules as security artifact
- `#81` Add startup validation for runtime directory and socket ownership invariants
- `#82` Add security release gate for policy, polkit and hardening verification

Abhaengigkeiten:

- sollte parallel zu Phase B geplant, aber spaetestens vor produktiver Freigabe abgeschlossen werden
- der Release-Gate-Check wird als versioniertes Script `scripts/verify_security_release_gate.sh` gefuehrt und in `artifact`- sowie `live`-Pruefung gesplittet

### Phase D: P1/P2 Audit / Logging / Information Leakage

Ziel:

- Audit robuster machen
- sensible Datenabfluesse begrenzen
- Fehlersituationen sichtbarer und sicherer machen

Enthaelt:

- `#79` Add audit flood protection for repetitive invalid requests
- `#80` Add journald output size guardrails
- `#86` Define audit retention, integrity and journald exposure procedure

Abhaengigkeiten:

- profitiert von Phase A und C, ist aber teilweise parallel bearbeitbar

### Phase E: P2/P3 Additional Hardening / Defense in Depth

Ziel:

- verbleibende lokale Angriffsoberflaeche weiter reduzieren
- Betriebsleitplanken fuer spaetere Erweiterungen definieren

Enthaelt:

- `#85` Extend systemd hardening beyond current baseline
- `#87` Classify read-only action sensitivity and default policy guidance

Abhaengigkeiten:

- keine harten technischen Blocker, aber sinnvoll erst nach den Kernphasen

## Konkrete Reihenfolge der Security-Upgrades

1. Phase A komplett abschliessen.
2. Die P0-Themen aus Phase B und C abschliessen.
3. Produktionsfreigabe nur erwaegen, wenn alle P0-Issues geschlossen und deployt sind.
4. Direkt danach P1-Themen aus Phase B, C und D umsetzen.
5. P2 und P3 als Defense-in-Depth sauber nachziehen.

## P0-Blocker fuer "hoch sicher produktionsreif"

Die folgenden Issues muessen zwingend geschlossen sein:

- `#71` Enforce maximum IPC frame size
- `#72` Add IPC socket read timeout
- `#73` Add IPC socket write timeout
- `#74` Add local admission control for IPC flooding
- `#75` Bind request metadata to peer credentials for security decisions
- `#76` Validate policy file owner and mode at startup
- `#77` Version and document polkit rules as security artifact

Zusatzbedingungen fuer die reale Freigabe:

- gehärtete `adminbotd.service` ist auf dem Zielsystem aktiv deployt
- Policy-Datei ist root-kontrolliert und durch AdminBot beim Start validiert
- polkit-Regeln sind versioniert, reviewed und enger als oder gleich der lokalen AdminBot-Policy
- Runtime-Verzeichnis und Socket-Rechte sind betrieblich korrekt gesetzt
- Release-Gate fuer Hardening und Security-Artefakte ist Teil des Freigabeprozesses
- sowohl der `artifact`- als auch der `live`-Modus des Security-Release-Gates muessen erfolgreich sein

## P1-Themen, die in v1.0.x sehr zeitnah folgen sollen

- `#78` Enforce max_parallel_mutations at runtime
- `#79` Add audit flood protection for repetitive invalid requests
- `#80` Add journald output size guardrails
- `#81` Add startup validation for runtime directory and socket ownership invariants
- `#82` Add security release gate for policy, polkit and hardening verification

Diese Punkte sind keine unmittelbaren Architekturblocker wie die P0-Themen, aber sie sind fuer eine belastbare Produktionshärtung sehr wichtig.

## P2 und P3

### P2

- `#83` Add mutating request replay and idempotency strategy
- `#84` Persist restart abuse counters across daemon restarts
- `#85` Extend systemd hardening beyond current baseline
- `#86` Define audit retention, integrity and journald exposure procedure

### P3

- `#87` Classify read-only action sensitivity and default policy guidance

## Production-Readiness-Urteil

### Aktueller Stand

AdminBot darf aktuell nicht als "hoch sicher fuer produktiven Einsatz" eingestuft werden.

### Begruendung

- die P0-Grenzen fuer IPC, Peer-Bindung, Policy-Datei und polkit-Artefakte sind geschlossen
- verbleibende P1-Haertung fuer Audit, Informationsabfluss und weitergehende Betriebsleitplanken ist noch offen
- ein Live-Release-Gate kann reale Deployment-Blocker weiterhin sichtbar machen und muss vor produktiver Freigabe gruen sein

### Belastbare Freigabe erst nach

- Abschluss aller P0-Issues
- erfolgreichem Deployment- und Release-Gate
- dokumentierter und gepruefter polkit-, Policy- und systemd-Konfiguration auf dem Zielsystem

## Milestone-Zuordnung

- `v1.0.1 - Security Hardening P0`
  - `#71` bis `#77`
- `v1.0.2 - Security Hardening P1`
  - `#78` bis `#82`
- `v1.1.0 - Defense in Depth`
  - `#83` bis `#87`

## Kurzfazit

Die Roadmap priorisiert zuerst die echten Sicherheitsgrenzen:

- IPC-Verfuegbarkeit
- Identitaetsbindung
- Deployment- und Privilegbruecken-Haertung

Erst danach folgen tiefere Betriebs- und Defense-in-Depth-Massnahmen. Diese Reihenfolge ist bewusst konservativ und auf eine reale produktive Haertung ausgelegt.

# AdminBot v2 Threat Model

## Scope

Dieses Threat Model bewertet den aktuellen Stand von `adminbotd` auf Basis von:

- `docs/adminbot_v2/*`
- der aktuellen Rust-Implementierung unter `src/`
- der aktuellen `adminbotd.service`

Nicht im Scope:

- generische Linux-Haertung des Gesamtsystems
- vollständige Prüfung externer polkit-Regeln
- Supply-Chain-Themen außerhalb des Repositorys

## Annahmen

- `adminbotd` läuft als nicht-root Benutzer `adminbot`.
- der Socket `/run/adminbot/adminbot.sock` ist lokal und mit `0660` sowie Gruppe `adminbotctl` bereitgestellt.
- `/etc/adminbot/policy.toml` ist durch Deployment root-kontrolliert und nicht durch unprivilegierte lokale Benutzer schreibbar.
- polkit ist eng genug konfiguriert, um nur die beabsichtigten systemd-D-Bus-Operationen zu erlauben.
- `Agent-NN` spricht AdminBot nur lokal an und erhält keine direkte Root-Schnittstelle.

## Systemuebersicht

AdminBot v2 ist ein lokaler Rust-Daemon mit klar begrenzter Verantwortlichkeit:

- Requests kommen nur ueber einen Unix Domain Socket an.
- Requests sind JSON-basiert und versioniert.
- jede Action wird ueber eine statische Registry identifiziert.
- jede Action wird validiert, policy-geprueft und auditiert.
- privilegierte Service-Steuerung laeuft ueber systemd D-Bus plus polkit.
- es gibt keinen generischen Command-Runner, keine freie Shell, kein Plugin-System und kein LLM im Core.

## Datenfluesse

### Hauptfluss

1. Lokaler Client verbindet sich zu `/run/adminbot/adminbot.sock`
2. `adminbotd` liest den length-prefixed Frame
3. `adminbotd` ermittelt Peer-Credentials ueber `SO_PEERCRED`
4. JSON wird in `Request` deserialisiert
5. Action-Name und Action-Parameter werden validiert
6. `PolicyEngine` prueft Action-Freigabe und Capability-Mapping
7. der passende Action-Handler spricht lokale Backends an:
   - `/proc`, `/sys`, `statvfs`, Netzwerkstatus
   - journald API
   - systemd D-Bus
8. Audit-Ereignis wird an journald geschrieben, mit stderr-Fallback
9. strukturierte Response geht ueber denselben Socket an den Client zurueck

### Privilegierter Spezialfluss fuer `service.restart`

1. Client sendet `service.restart`
2. Request wird validiert, inklusive Unit-Name und non-empty `reason`
3. Policy prueft:
   - Action erlaubt
   - `service_control` Capability vorhanden
   - Unit auf Whitelist
   - Cooldown
   - Rate-Limit
4. `adminbotd` verbindet sich zum System-Bus
5. Aufruf: `org.freedesktop.systemd1.Manager.RestartUnit(unit, "replace")`
6. systemd/polkit entscheiden ueber die echte Privilegbruecke
7. `adminbotd` liest Pre- und Post-Status und auditiert Ergebnis

## Assets

### Systemintegritaet

- keine freie Codeausfuehrung
- keine unkontrollierte Root-Ausweitung
- kontrollierte Sicht auf lokale Systeminformationen

### Service Control

- Whitelist der erlaubten Units
- kontrollierte Restart-Semantik
- Schutz gegen Restart-Spam und Missbrauch

### Policy Enforcement

- korrekte Zuordnung von lokalen Peers zu Policy-Clients
- korrekte Capability-Pruefung
- Schutz gegen Policy-Bypass

### Audit Logs

- Vollstaendigkeit fuer sicherheitsrelevante Requests
- Unverfaelschbarkeit der Semantik
- ausreichende Daten fuer Incident-Analyse

### Verfuegbarkeit des Daemons

- IPC darf nicht trivial blockierbar sein
- der Daemon darf nicht durch einzelne Requests oder Flooding ausfallen

## Angreiferprofile

### Lokaler unprivilegierter Benutzer

Ziel:

- Daten lesen, die nicht fuer ihn bestimmt sind
- erlaubte Grenzen der Action Registry umgehen
- Restart-Rechte erschleichen
- Denial of Service gegen den Daemon ausloesen

Faehigkeiten:

- lokaler Socket-Zugriff, falls Gruppenmitgliedschaft oder Fehlkonfiguration vorliegt
- kontrollierte JSON-Requests
- viele Verbindungen und grosse Payloads

### Kompromittierter Prozess auf demselben Host

Ziel:

- vorhandene Unix-Identitaet missbrauchen
- `requested_by` oder Action-Parameter faelschen
- legitime lokale Rechte eskalieren

Faehigkeiten:

- gleiche UID/GID wie ein erlaubter Client
- hoher Request-Durchsatz
- gezielte Nutzung bereits vorhandener Policy-Freigaben

### Boesartiger Agent ueber Agent-NN

Ziel:

- semantisch legitime, aber operativ schaedliche Requests erzeugen
- Audit- und Policy-Limits austesten
- harmlos wirkende Read-only-Endpoints zur Informationssammlung missbrauchen

Faehigkeiten:

- strukturierte Requests im erlaubten API-Rahmen
- hohe Wiederholungsrate
- Nutzung von Korrelationen und Vorwissen ueber Systemzustand

## STRIDE-Matrix

| Kategorie | Zielbereich | Beispiel | Aktueller Schutz | Restrisiko |
| --- | --- | --- | --- | --- |
| Spoofing | Client-Identitaet | Client setzt `requested_by.type` oder `requested_by.id` frei | `SO_PEERCRED`, Policy-Mapping auf Unix-User/Group | Mittel bis hoch, weil `requested_by` nicht kryptografisch oder systemisch gebunden ist |
| Tampering | Policy/Unit/Logs | Manipulation von `/etc/adminbot/policy.toml`, polkit-Regeln oder Unit-Datei | Annahme root-kontrollierter Deployment-Artefakte | Hoch, falls Deployments unsauber sind; im Code selbst kaum Gegenkontrollen |
| Repudiation | Nachvollziehbarkeit | Client bestreitet mutierenden Request | Audit-Events fuer `received` und `completed`, Peer UID/GID/PID im Log | Mittel, weil Request-Authentizitaet oberhalb von Peer-Creds begrenzt ist |
| Information Disclosure | journald, Prozess- und Service-Daten | Auslesen sensibler Systeminformationen ueber erlaubte Read-Endpoints | statische Action Registry, Capability-Pruefung, Unit-Whitelist fuer Journal | Mittel, weil keine Feld-Redaktion oder Message-Groessenbegrenzung existiert |
| Denial of Service | IPC und Handler | grosse Frames, Slowloris-artige Reads, Socket-Flooding, serielle Blockade | Request-Validierung und einige Per-Action-Limits | Hoch, weil keine globale Payload-Grenze, keine Socket-Timeouts, keine Parallelitaets- oder Admission-Control |
| Elevation of Privilege | `service.restart` | polkit-Fehlkonfiguration oder Policy-Bypass fuehrt zu unberechtigtem Restart | Whitelist, Capability-Pruefung, Cooldown, Rate-Limit, D-Bus statt Shell | Mittel, stark abhaengig von korrekter polkit-Konfiguration und Client-Identitaetsbindung |

## Bedrohungsmatrix

| Bedrohung | Asset | Angreifer | Wahrscheinlichkeit | Auswirkung | Bewertung |
| --- | --- | --- | --- | --- | --- |
| Selbstdeklarierte `requested_by.type` wird zur Berechtigungsbeeinflussung missbraucht | Policy Enforcement | kompromittierter lokaler Prozess | Mittel | Hoch | Hoch |
| Uebergrosse IPC-Frames fuehren zu Speicher- oder Blockadeeffekten | Verfuegbarkeit | lokaler Benutzer | Hoch | Mittel bis hoch | Hoch |
| Einzelner langsamer Socket-Client blockiert den Daemon | Verfuegbarkeit | lokaler Benutzer | Hoch | Hoch | Hoch |
| polkit-Regel ist breiter als die AdminBot-Policy | Service Control | lokaler Benutzer mit D-Bus-Zugang | Mittel | Hoch | Hoch |
| Policy-Datei wird lokal manipuliert | Policy Enforcement | lokaler Benutzer mit Fehlrechten oder kompromittiertem Deploy | Niedrig bis mittel | Hoch | Hoch |
| journald enthaelt sensible Inhalte und wird ueber `journal.query` exfiltriert | Informationsschutz | erlaubter Client | Mittel | Mittel | Mittel |
| Restart-Cooldown wird durch Mehrprozess- oder Neustart-Szenarien umgangen | Service Control | boesartiger Agent oder lokaler Prozess | Mittel | Mittel | Mittel |
| Audit-Fallback auf stderr liefert weniger robuste Persistenz als journald | Audit Logs | lokaler Betreiberfehler | Niedrig | Mittel | Niedrig bis mittel |
| D-Bus oder journald sind nicht verfuegbar | Verfuegbarkeit | Systemfehler | Mittel | Mittel | Mittel |
| Action- oder Parameterausweitung durch unbekannte Felder | Integritaet | lokaler Benutzer | Niedrig | Mittel | Niedrig, weil `deny_unknown_fields` und explizite Param-Deserialisierung greifen |

## Zusammenfassung

Die Architektur ist fuer lokale Least-Privilege-Verwaltung stark:

- statische Action Registry statt Shell
- non-root Daemon
- lokale IPC
- D-Bus/polkit statt Root-Exec
- strukturierte Auditierung

Die wichtigsten offenen Risiken liegen nicht in "klassischer Remote-RCE", sondern in:

- lokaler Verfuegbarkeit
- Identitaetsbindung zwischen Request-Metadaten und echtem Peer
- Betriebs- und Deploy-Sicherheit rund um Policy, polkit und systemd

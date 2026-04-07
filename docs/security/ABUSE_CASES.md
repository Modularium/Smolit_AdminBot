# AdminBot v2 Abuse Cases

## Bewertungsskala

- `low`: begrenzte Auswirkungen oder bereits gut eingegrenzt
- `medium`: realistisch ausnutzbar, aber mit vorhandenen Huerden
- `high`: realistisch und mit deutlich sicherheitsrelevanten Auswirkungen

## 1. Restart-Spam trotz Cooldown umgehen

### Angriffsbeschreibung

Ein Angreifer versucht, wiederholt `service.restart` fuer eine erlaubte Unit auszufuehren, um Verfuegbarkeit zu stoeren oder Betriebsdruck zu erzeugen.

### Aktueller Schutz

- Unit-Whitelist
- Cooldown pro Unit
- Rate-Limit pro Stunde
- Audit fuer Eingang und Ergebnis

### Risiko-Level

- `medium`

### Empfehlung

- Cooldown- und Rate-Limit-Zustaende optional persistent machen
- globale Metrik oder Alarmierung fuer haeufige Restart-Anfragen einfuehren

## 2. Whitelist umgehen

### Angriffsbeschreibung

Ein Angreifer versucht, eine nicht erlaubte Unit ueber semantisch aehnliche Namen oder ungewoehnliche Zeichen durchzuschleusen.

### Aktueller Schutz

- `validate_unit()` begrenzt Zeichenmenge und erzwingt `.service`
- Policy-Whitelist prueft exakte Namen

### Risiko-Level

- `low`

### Empfehlung

- exakte Vergleichslogik beibehalten
- optional kanonische Namensdarstellung dokumentieren

## 3. Service-Name-Injection

### Angriffsbeschreibung

Ein Angreifer probiert Sonderzeichen, Spaces oder Shell-Metazeichen in `params.unit`, um Backend-Kommandos oder systemd semantisch zu beeinflussen.

### Aktueller Schutz

- keine Shell-Nutzung
- Unit-Validierung erlaubt nur ASCII alphanumerisch plus `.`, `-`, `_`, `@`
- `.service` ist Pflicht

### Risiko-Level

- `low`

### Empfehlung

- aktuelle strikte Validierung unveraendert beibehalten

## 4. Socket Flooding

### Angriffsbeschreibung

Ein lokaler Prozess oeffnet viele Verbindungen oder sendet unvollstaendige Frames, um `adminbotd` zu blockieren.

### Aktueller Schutz

- lokaler Socket statt Netzwerkport
- Dateirechte

### Risiko-Level

- `high`

### Empfehlung

- maximale Frame-Groesse einfuehren
- Socket-Read-/Write-Timeouts setzen
- Verbindungs- oder Request-Limits pro Peer ergaenzen

## 5. Replay von Requests

### Angriffsbeschreibung

Ein erlaubter lokaler Client wiederholt einen bereits erfolgreichen Request oder nutzt die gleiche fachliche Operation mehrfach mit neuen IDs.

### Aktueller Schutz

- `request_id` muss UUID sein
- Cooldown und Rate-Limit nur fuer `service.restart`

### Risiko-Level

- `medium`

### Empfehlung

- klar dokumentieren, dass `request_id` aktuell nur Korrelation und kein Replay-Schutz ist
- fuer mutierende Actions optional Replay- oder Idempotenz-Strategie definieren

## 6. Privilege Escalation via polkit-Fehlkonfiguration

### Angriffsbeschreibung

Die lokale Policy ist korrekt, aber polkit erlaubt mehr als beabsichtigt. Ein Angreifer mit geeignetem lokalen Kontext koennte so effektiv mehr Neustarts ausloesen als fachlich vorgesehen.

### Aktueller Schutz

- AdminBot begrenzt den D-Bus-Aufruf auf `RestartUnit(unit, "replace")`
- lokale Whitelist und Capability-Pruefung

### Risiko-Level

- `high`

### Empfehlung

- polkit-Regeln als explizites Security-Artefakt versionieren und reviewen
- Deployment-Review als Freigabekriterium behandeln

## 7. Manipulation von Policy-Dateien

### Angriffsbeschreibung

Ein lokaler Angreifer oder Deploy-Fehler erweitert die Policy-Datei, um zusaetzliche Actions, Units oder Capabilities freizugeben.

### Aktueller Schutz

- striktes TOML-Schema
- unbekannte Felder werden abgewiesen

### Risiko-Level

- `high`

### Empfehlung

- Dateirechte, Eigentuemerschaft und Bereitstellung der Policy explizit absichern
- optional Policy-Hashing oder Signierung fuer spaetere Versionen pruefen

## 8. Spoofing von `requested_by.type`

### Angriffsbeschreibung

Ein lokaler Prozess gibt sich in der Request-Metadatenstruktur als `human` statt `agent` aus, wenn die Policy dieselbe Unix-Identitaet unterschiedlich behandelt.

### Aktueller Schutz

- Peer-Credentials werden separat erhoben
- Audit loggt Peer-UID/GID/PID

### Risiko-Level

- `high`

### Empfehlung

- `requested_by.type` nicht allein fuer Sicherheitsentscheidungen nutzen
- Policy staerker an echte OS-Identitaeten binden

## 9. Sensitive Data Exposure via `journal.query`

### Angriffsbeschreibung

Ein berechtigter, aber neugieriger Client nutzt `journal.query`, um sensible oder betriebliche Informationen aus Journald-Nachrichten auszulesen.

### Aktueller Schutz

- Capability `read_sensitive`
- optionale Unit-Whitelist fuer Journal-Filter
- Limit und Zeitfenster

### Risiko-Level

- `medium`

### Empfehlung

- Sensitivitaet von Journal-Zugriff in Deployment und Policy konservativ behandeln
- spaeter Redaktions- oder Feldfilteroptionen evaluieren

## 10. DoS durch grosse JSON- oder Journal-Payloads

### Angriffsbeschreibung

Ein Angreifer nutzt sehr grosse Eingaben oder ungewoehnlich grosse Journal-Nachrichten, um Speicher- und CPU-Last zu erhoehen.

### Aktueller Schutz

- einige action-spezifische Limits, z. B. Journal-Count und Process-Count

### Risiko-Level

- `medium`

### Empfehlung

- globale Groessenlimits fuer Request-Frames und ausgehende Datensaetze dokumentieren und spaeter umsetzen

## 11. Audit-Umgehung durch journald-Ausfall

### Angriffsbeschreibung

Journald ist nicht verfuegbar oder reagiert fehlerhaft; ein Angreifer profitiert von schwacher Audit-Persistenz.

### Aktueller Schutz

- Fallback-JSON ueber stderr

### Risiko-Level

- `medium`

### Empfehlung

- Betriebsdokumentation fuer Audit-Ausfall definieren
- optional zweiten lokalen Audit-Sink spaeter erwägen

## 12. Multi-Action-DoS durch fehlende globale Mutationsbegrenzung

### Angriffsbeschreibung

Die Policy kennt `max_parallel_mutations`, aber der aktuelle Daemon erzwingt diese Grenze nicht aktiv. Bei spaeteren Erweiterungen koennte das unbemerkt kritisch werden.

### Aktueller Schutz

- Daemon ist derzeit sequentiell
- nur eine mutierende Action in v1

### Risiko-Level

- `medium`

### Empfehlung

- als explizite Architektur- und Code-Schuld dokumentieren
- vor jeder spaeteren Parallelisierung zwingend aktiv erzwingen

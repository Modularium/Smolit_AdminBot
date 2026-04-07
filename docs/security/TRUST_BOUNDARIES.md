# AdminBot v2 Trust Boundaries

## Zweck

Dieses Dokument beschreibt die expliziten Vertrauensgrenzen von AdminBot v2. Der Fokus liegt auf:

- wer wem vertraut
- was vor Grenzueberschreitung validiert wird
- wodurch Trust verletzt werden kann

## Uebersicht

Die zentrale Sicherheitsgrenze liegt nicht zwischen mehreren Netzwerken, sondern lokal zwischen:

- lokalen Clients
- `adminbotd`
- den System-Backends des Linux-Hosts

## Boundary 1: Client <-> AdminBot ueber IPC

### Beteiligte

- lokale CLI oder lokaler Integrationsprozess
- `adminbotd`
- Unix Socket `/run/adminbot/adminbot.sock`

### Vertrauensmodell

- der Client wird nicht als "ehrlich" angenommen
- `adminbotd` vertraut dem Socket-Zugriff allein nicht
- `adminbotd` vertraut primär:
  - `SO_PEERCRED`
  - Policy-Zuordnung auf Basis von Unix-User und Unix-Gruppen

### Aktuelle Validierung

- Socket-Modus `0660`
- Gruppe `adminbotctl`
- Peer-Credentials via `SO_PEERCRED`
- Request-Deserialisierung mit `deny_unknown_fields`
- Version-Check
- UUID-Check fuer `request_id`
- Action-Name gegen statische Registry
- action-spezifische Param-Validierung

### Trust-Risiken

- `requested_by.type` und `requested_by.id` sind vom Client gesetzt und nicht an den Peer gebunden
- es gibt keine kryptografische oder OS-seitige Bindung zwischen deklarierter Identitaet und realem Prozess
- es gibt keine globale Payload-Grenze
- es gibt keine Read-/Write-Timeouts pro Verbindung
- der Server verarbeitet Verbindungen sequentiell

### Moegliche Trust-Verletzungen

- ein lokaler Prozess mit erlaubter Unix-Identitaet kann sich semantisch als anderer Clienttyp ausgeben
- ein lokaler Prozess kann den Daemon durch langsame oder grosse Requests blockieren
- ein lokaler Prozess kann Request-Metadaten fuer Audit und Korrelation frei waehlen

## Boundary 2: AdminBot <-> systemd ueber D-Bus

### Beteiligte

- `adminbotd`
- `org.freedesktop.systemd1.Manager`
- System-Bus

### Vertrauensmodell

- `adminbotd` vertraut systemd als autoritativer Backend-Komponente
- systemd vertraut AdminBot nicht blind, sondern nutzt D-Bus plus polkit
- `adminbotd` muss vor dem D-Bus-Aufruf fachlich alles lokal entscheiden

### Aktuelle Validierung

- nur `service.restart`
- nur `RestartUnit`
- nur Mode `"replace"`
- Unit-Name-Validierung
- lokale Policy-Whitelist
- Capability-Check
- Cooldown und Rate-Limit
- Pre- und Post-Status-Pruefung

### Trust-Risiken

- polkit-Konfiguration liegt ausserhalb des Rust-Cores
- falsche polkit-Regeln koennen die lokale Policy absichern oder unterlaufen
- D-Bus-Fehler werden zu strukturierten Fehlern gemappt, aber nicht weiter eingegrenzt

### Moegliche Trust-Verletzungen

- zu breite polkit-Regeln erlauben Neustarts ausserhalb der beabsichtigten Freigabe
- wenn Deployment und Policy auseinanderlaufen, entsteht ein Drift zwischen lokaler Autorisierung und Systemautoritaet

## Boundary 3: AdminBot <-> Filesystem

### Beteiligte

- `/etc/adminbot/policy.toml`
- `/run/adminbot/adminbot.sock`
- `/var/lib/adminbot`
- optionale Audit-/Runtime-Dateien

### Vertrauensmodell

- `adminbotd` vertraut auf korrekte Dateirechte und saubere Provisionierung
- das Dateisystem wird nicht im Code selbst als vertrauenswuerdig validiert

### Aktuelle Validierung

- Policy-Datei wird beim Start geladen
- TOML nutzt `deny_unknown_fields`
- Policy-Version muss `1` sein
- Socket-Rechte werden beim Binden gesetzt
- Socket-Gruppe wird aktiv auf `adminbotctl` gesetzt

### Trust-Risiken

- keine Pruefung von Dateieigentuemer, Modus oder Unveraenderbarkeit der Policy-Datei
- keine Integritaetspruefung der Policy-Datei
- vorhandener Socket-Pfad wird vor neuem Bind entfernt

### Moegliche Trust-Verletzungen

- manipulierte Policy-Datei kann Rechte ausweiten
- unsaubere Runtime-Verzeichnisse koennen Socket-Zugriff oder Neustarts beeinflussen
- falsch provisionierte Dateirechte koennen das Sicherheitsmodell unterlaufen

## Boundary 4: AdminBot <-> journald

### Beteiligte

- `adminbotd`
- journald Lesepfad fuer `journal.query`
- journald Schreibpfad fuer Audit

### Vertrauensmodell

- `adminbotd` vertraut journald als System-Backend fuer Audit und Log-Abfrage
- `journal.query` vertraut den Journaldaten semantisch nur begrenzt

### Aktuelle Validierung

- Unit-Filter nur ueber `_SYSTEMD_UNIT=...`
- Unit wird vorab gegen Policy geprueft
- Limit und Zeitfenster werden validiert
- Audit schreibt strukturierte journald-Felder
- Fallback auf JSON ueber stderr, falls journald nicht verfuegbar ist

### Trust-Risiken

- Log-Inhalte koennen sensible Daten enthalten
- es gibt keine Redaktionslogik fuer Journal-Nachrichten
- es gibt keine Groessenbegrenzung einzelner Nachrichten im Ergebnis

### Moegliche Trust-Verletzungen

- erlaubte Clients koennen sensible Journaldaten exfiltrieren
- Log-Inhalte koennen fuer soziale oder operative Irrefuehrung missbraucht werden

## Boundary 5: AdminBot <-> polkit

### Beteiligte

- `adminbotd`
- polkit-Regeln des Zielsystems
- systemd D-Bus-Aufrufkette

### Vertrauensmodell

- `adminbotd` verlaesst sich auf polkit nur als schmale Privilegbruecke
- polkit darf die fachliche Policy nicht ersetzen

### Aktuelle Validierung

- im Repository selbst keine polkit-Regeln
- die Architektur fordert enge, schmale Regeln
- AdminBot reduziert den Scope auf `RestartUnit(unit, "replace")`

### Trust-Risiken

- die wichtigste Privileggrenze liegt in einem externen Betriebsartefakt
- eine zu breite polkit-Regel kann die lokale Schutzwirkung erheblich reduzieren

### Moegliche Trust-Verletzungen

- Fehlkonfiguration erlaubt Neustarts fuer unerwuenschte Units
- Fehlkonfiguration erlaubt Zugriffe fuer unerwuenschte lokale Identitaeten

## Boundary 6: AdminBot <-> Agent-NN

### Beteiligte

- lokaler Agent-Prozess oder dedizierter AdminBot-Adapter
- `adminbotd`

### Vertrauensmodell

- Agent-NN ist nicht vertrauenswuerdig per se
- AdminBot ist die technische und fachliche Sicherheitsgrenze
- ein Agent-Aufruf ist nur ueber einen dedizierten, fest gemappten Tool-Pfad akzeptabel

### Aktuelle Validierung

- keine eigene Agent-API
- gleiche IPC-Regeln wie fuer andere lokale Clients
- `SO_PEERCRED` und Policy-Mapping auf `unix_user` oder `unix_group` bleiben autoritativ
- `requested_by.type` und `requested_by.id` bleiben Audit- und Korrelation-Metadaten
- in der Dokumentation ist die erste Agent-Freigabe auf eine kleine dedizierte Toolflaeche begrenzt
- `service.restart` ist fuer Agent-NN nicht Teil der Default-Freigabe
- zusaetzliche Hardening-Layer im Core:
  - per-Identity Rate Limit
  - optionales per-Tool Rate Limit
  - Replay-Reject ueber `request_id`
  - Preview-vor-Execute-Guard fuer `service.restart`

### Trust-Risiken

- wenn Agent-NN unter derselben Unix-Identitaet wie ein privilegierter Human-Client laeuft, wird die Trust-Grenze unschaerfer
- `requested_by.type` ist selbsterklaert
- Policy-Matches werden vereinigt; ueberlappende Human- und Agent-Gruppen koennen Capabilities ungewollt addieren
- ungebremste Agent-Loops koennen ansonsten lokale IPC- und Diagnostikpfade fluten
- wiederverwendete Request-IDs oder fehlende Preview-Links koennen ansonsten Mutationsschutz aushebeln

### Moegliche Trust-Verletzungen

- Agent kann sich als `human` ausgeben, falls Policy-Mapping dieselbe Unix-Identitaet nutzt
- Agent erbt ueber eine gemeinsame Gruppe dieselben oder weitere Human-Capabilities, obwohl nur Socket-Zugriff beabsichtigt war
- identische Request-IDs werden wiederverwendet, um Mutationen zu wiederholen
- Restart-Requests werden ohne vorangehende Preview abgesetzt

### Integrationsregel

- Agent-NN spricht AdminBot nur ueber einen dedizierten Adapter mit festem Tool-Mapping an
- kein generischer Action-Passthrough
- keine Shell
- keine direkte systemd- oder polkit-Steuerung ausserhalb von AdminBot
- Rate Limits, Replay-Schutz und Mutation Guards bleiben im AdminBot-Core und werden nicht an den Adapter delegiert

## Fazit

Die staerksten Grenzen sind:

- non-root Daemon
- lokale IPC
- statische Action Registry
- systemd D-Bus plus polkit statt Shell

Die schwaechsten Grenzen sind:

- Identitaetsbindung auf IPC-Ebene
- Betriebskonfiguration ausserhalb des Repo, besonders polkit und Policy-Dateirechte
- Verfuegbarkeit gegen lokale DoS-Angriffe

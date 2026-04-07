# AdminBot v1 Audit Retention and Journald Exposure Procedure

## Scope

Dieses Dokument beschreibt den minimalen, verbindlichen Betriebsprozess fuer:

- Audit-Aufbewahrung
- Integritaet und Export
- Journald-Exposure
- Incident-Nachvollziehbarkeit

Es gilt fuer AdminBot v1.x ohne externe SIEM- oder zentrale Logging-Plattform.

## Zielbild

AdminBot-Audits sollen:

- nachvollziehbar bleiben
- nicht still verschwinden
- nicht unkontrolliert breit lesbar sein
- fuer Incident Response reproduzierbar exportierbar sein

## Quelle der Audit-Daten

Primäre Audit-Quelle:

- journald-Eintraege von `adminbotd`

Erwartete Eigenschaften:

- strukturierte Felder aus dem AdminBot-Audit-Logger
- echte Peer-UID/GID/PID
- Policy-/Capability-Entscheidungen
- Success-/Error-Stufen
- Suppressionsmarker bei Flood-Schutz

## Verbindliche Aufbewahrung

Mindestens gefordert:

1. journald muss persistent gespeichert werden, nicht nur fluechtig im RAM
2. AdminBot-Auditdaten muessen mindestens `30 Tage` lokal vorgehalten werden
3. Groessen- oder Rotationsgrenzen duerfen Auditdaten nicht schon nach wenigen Stunden verdrängen
4. Drift in Journald-Retention ist als Security- und Betriebsproblem zu behandeln

Empfohlene Operator-Praxis:

- `Storage=persistent`
- Retention so waehlen, dass `30 Tage` fuer den erwarteten Host gesichert bleiben
- Groessenlimits bewusst dokumentieren und reviewen

## Journald-Exposure

AdminBot begrenzt `journal.query` bereits technisch. Betrieblich bleibt trotzdem verbindlich:

1. `read_sensitive` nur restriktiv vergeben
2. Zugriff auf journald ausserhalb von AdminBot nur fuer klar benannte Admin-Identitaeten erlauben
3. Mitgliedschaften in Gruppen mit Journal-Zugriff regelmaessig pruefen
4. keine pauschale Weitergabe von Audit-Exports an untrusted Operator- oder Agent-Kontexte

Annahme:

- Die konkrete Rechtevergabe fuer Journal-Lesen ist distributionsabhaengig und muss im Zielsystem sauber dokumentiert werden.

## Integritaet und Incident-Export

AdminBot v1 fuehrt keine eigene Hash-Chain ein. Deshalb gilt fuer Incident Response:

1. relevante Auditdaten zeitnah aus journald exportieren
2. Export nur read-only und reproduzierbar erzeugen
3. Export mit separater Prüfsumme dokumentieren
4. Exportpfad, Zeitpunkt, verantwortliche Person und betroffene `request_id` festhalten

Minimaler Incident-Export:

```bash
journalctl -u adminbotd --since '2026-01-01 00:00:00' --until '2026-01-01 23:59:59' -o json > adminbotd-audit.json
sha256sum adminbotd-audit.json > adminbotd-audit.json.sha256
```

## Betriebsregeln

Vor produktivem Einsatz:

- journald-Persistenz pruefen
- Retention dokumentieren
- Verantwortliche fuer Audit-Zugriff benennen
- `read_sensitive` und systemweiten Journal-Zugriff getrennt reviewen

Im Betrieb:

- Audit-Retention mindestens je Release und je Policy-Aenderung erneut pruefen
- groessere Journald-Rotations- oder Storage-Aenderungen als Security-relevant behandeln
- Export nur fuer Incident, Review oder forensische Analyse erzeugen

## Nicht Ziel

Dieses Dokument fuehrt nicht ein:

- externe SIEM-Anbindung
- zentrale Log-Pipeline
- kryptografische Unveraenderlichkeitsgarantie innerhalb von AdminBot selbst

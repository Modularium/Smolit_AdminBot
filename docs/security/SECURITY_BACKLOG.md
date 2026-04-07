# AdminBot Security Backlog

## Zweck

Dieses Backlog konsolidiert die Findings aus:

- `THREAT_MODEL.md`
- `TRUST_BOUNDARIES.md`
- `ATTACK_SURFACES.md`
- `ABUSE_CASES.md`
- `SECURITY_REVIEW_V1.md`
- `HARDENING_CHECKLIST.md`

Jeder Eintrag ist einem priorisierten GitHub-Issue zugeordnet, soweit bereits angelegt.

## IPC / Verfuegbarkeit

### Harte Begrenzung eingehender IPC-Frames

- Kategorie: IPC / Verfuegbarkeit
- Risiko: Speicher- und Verfuegbarkeitsangriff ueber ubergrosse Frames
- Prioritaet: `P0`
- Kurzbeschreibung: Die aktuelle IPC-Grenze erlaubt length-prefixed Nachrichten ohne harte globale Groessenobergrenze.
- Empfehlung: verbindliche Maximalgroesse definieren und technisch erzwingen.
- GitHub-Issue: `#71`

### Socket-Read-Timeouts

- Kategorie: IPC / Verfuegbarkeit
- Risiko: Slow-Client-DoS beim Einlesen von Frames
- Prioritaet: `P0`
- Kurzbeschreibung: Langsame oder absichtlich blockierende Clients koennen die sequentielle Verarbeitung ausbremsen.
- Empfehlung: konservative Read-Timeouts definieren und sauber behandeln.
- GitHub-Issue: `#72`

### Socket-Write-Timeouts

- Kategorie: IPC / Verfuegbarkeit
- Risiko: blockierende Rueckkanal-Schreibvorgaenge
- Prioritaet: `P0`
- Kurzbeschreibung: Langsame Empfaenger oder volle Puffer koennen Antwortpfade festhalten.
- Empfehlung: Write-Timeouts mit klaren Fehlerpfaden einfuehren.
- GitHub-Issue: `#73`

### Lokale Admission-Control gegen Flooding

- Kategorie: IPC / Verfuegbarkeit
- Risiko: lokale Verbindungs- oder Request-Floods
- Prioritaet: `P0`
- Kurzbeschreibung: Die serielle Architektur ist einfach, aber lokal leichter blockierbar.
- Empfehlung: Admission-Control und einfache Peer-bezogene Missbrauchsgrenzen einfuehren.
- GitHub-Issue: `#74`

## Identitaet / AuthZ / Capability-Bindung

### Request-Metadaten an echte Peer-Credentials binden

- Kategorie: Identitaet / AuthZ / Capability-Bindung
- Risiko: Security-Entscheidungen auf Basis selbstdeklarativer Metadaten
- Prioritaet: `P0`
- Kurzbeschreibung: `requested_by.type` und `requested_by.id` duerfen nicht ohne systemische Bindung sicherheitsrelevant sein.
- Empfehlung: Policy-Entscheidungen hart an Peer-UID, GID oder eine explizite lokale Bindungslogik koppeln.
- GitHub-Issue: `#75`

### `max_parallel_mutations` technisch erzwingen

- Kategorie: Parallelisierung / Race / Abuse Control
- Risiko: Modell und Laufzeit fallen auseinander
- Prioritaet: `P1`
- Kurzbeschreibung: Das Policy-Modell kennt eine Mutationsgrenze, die Runtime erzwingt sie aber noch nicht.
- Empfehlung: Laufzeitkontrolle fuer mutierende Aktionen einbauen.
- GitHub-Issue: `#78`

### Replay- und Idempotency-Strategie fuer mutierende Requests

- Kategorie: Identitaet / AuthZ / Capability-Bindung
- Risiko: Wiederholung mutierender Requests ohne starke Schutzstrategie
- Prioritaet: `P2`
- Kurzbeschreibung: `request_id` ist vorhanden, aber nicht als Replay- oder Idempotency-Schutz ausgearbeitet.
- Empfehlung: Strategie fuer Wiederholung, Korrelation und Ablehnung definieren.
- GitHub-Issue: `#83`

## Policy / Deployment / Betriebsartefakte

### Policy-Dateirechte beim Start validieren

- Kategorie: Policy / Deployment / Betriebsartefakte
- Risiko: Policy-Manipulation durch Fehlrechte oder Deploy-Fehler
- Prioritaet: `P0`
- Kurzbeschreibung: Der Code vertraut aktuell auf ein korrekt abgesichertes Deployment der Policy-Datei.
- Empfehlung: Owner- und Mode-Pruefung beim Start verpflichtend machen.
- GitHub-Issue: `#76`

### Runtime-Verzeichnis und Socket-Invarianten pruefen

- Kategorie: Policy / Deployment / Betriebsartefakte
- Risiko: Socket-Exposure durch falsche Rechte oder falschen Besitzer
- Prioritaet: `P1`
- Kurzbeschreibung: Security hängt stark an sauberen Rechten fuer `/run/adminbot` und den Socket.
- Empfehlung: Besitz, Modus und erwartete Laufzeitinvarianten aktiv validieren.
- GitHub-Issue: `#81`

## systemd / Hardening

### Weitere systemd-Haertung ueber die Baseline hinaus

- Kategorie: systemd / Hardening
- Risiko: verbleibende lokale Prozess-Angriffsoberflaeche
- Prioritaet: `P2`
- Kurzbeschreibung: Die aktuelle Unit ist solide, aber weitere Kernel-, Proc- und Syscall-Reduktionen sind moeglich.
- Empfehlung: zusaetzliche Hardening-Optionen gezielt pruefen und einführen.
- GitHub-Issue: `#85`

## Audit / Logging

### Audit-Flood-Schutz fuer invalide Requests

- Kategorie: Audit / Logging
- Risiko: Audit-Spam, Signalverlust und indirekter DoS
- Prioritaet: `P1`
- Kurzbeschreibung: Wiederholte invalide Requests koennen Audit-Volumen unverhaeltnismaessig aufblasen.
- Empfehlung: deduplizierende oder rate-limitierte Audit-Schutzmechanismen definieren.
- GitHub-Issue: `#79`

### Audit-Retention und Integritaetsverfahren

- Kategorie: Release / Betrieb / Security-Prozess
- Risiko: fehlende Nachvollziehbarkeit oder unzureichende Incident-Daten
- Prioritaet: `P2`
- Kurzbeschreibung: Journald als Audit-Sink braucht betriebliche Leitplanken fuer Aufbewahrung und Integritaet.
- Empfehlung: dokumentierte Betriebsprozedur fuer Retention, Export und Vorfallanalyse festlegen.
- GitHub-Issue: `#86`

## journald / Informationsabfluss

### Groessenbegrenzung fuer Journald-Ausgaben

- Kategorie: journald / Informationsabfluss
- Risiko: Datenabfluss und Speicher-/Response-Aufblaehung
- Prioritaet: `P1`
- Kurzbeschreibung: `journal.query` ist nach Count und Zeit begrenzt, aber nicht global nach Ausgabegroesse.
- Empfehlung: harte Antwort- und Feldgroessen-Guardrails definieren.
- GitHub-Issue: `#80`

### Sensitivitaet read-only Actions klassifizieren

- Kategorie: journald / Informationsabfluss
- Risiko: unterschätzter Datenabfluss ueber scheinbar harmlose Endpunkte
- Prioritaet: `P3`
- Kurzbeschreibung: Read-only bedeutet nicht automatisch unsensibel.
- Empfehlung: Deployment-Guidance und Standard-Policy fuer sensible Read-Endpoints dokumentieren.
- GitHub-Issue: `#87`

## polkit / Privilegbruecke

### polkit-Regeln als versioniertes Security-Artefakt behandeln

- Kategorie: polkit / Privilegbruecke
- Risiko: Privileg-Eskalation durch zu breite oder driftende polkit-Regeln
- Prioritaet: `P0`
- Kurzbeschreibung: Die D-Bus/ polkit-Bruecke ist zentral fuer `service.restart` und darf nicht ausser Kontrolle geraten.
- Empfehlung: Regeln versionieren, dokumentieren, reviewbar machen und explizit gegen AdminBot-Policy abgleichen.
- GitHub-Issue: `#77`

## Parallelisierung / Race / Abuse Control

### Restart-Missbrauch ueber Neustarts hinaus erschweren

- Kategorie: Parallelisierung / Race / Abuse Control
- Risiko: Abuse-Zaehler verlieren Wirkung nach Daemon-Neustart
- Prioritaet: `P2`
- Kurzbeschreibung: Cooldown und Rate-Limit sind vorhanden, aber nicht persistent.
- Empfehlung: Persistenz oder gleichwertige Betriebsstrategie fuer Missbrauchszaehler definieren.
- GitHub-Issue: `#84`

## Release / Betrieb / Security-Prozess

### Security-Release-Gate einfuehren

- Kategorie: Release / Betrieb / Security-Prozess
- Risiko: driftende Produktionssicherheit trotz sauberem Code
- Prioritaet: `P1`
- Kurzbeschreibung: Release-Freigaben brauchen explizite Pruefung von Policy, polkit, Hardening und Deployment-Invarianten.
- Empfehlung: Security-Gate in Release-Checkliste und Betriebsprozess verankern.
- GitHub-Issue: `#82`

## Prioritaetszusammenfassung

### P0

- `#71`
- `#72`
- `#73`
- `#74`
- `#75`
- `#76`
- `#77`

### P1

- `#78`
- `#79`
- `#80`
- `#81`
- `#82`

### P2

- `#83`
- `#84`
- `#85`
- `#86`

### P3

- `#87`

# AdminBot v1.0.x Security Sign-Off

## 1. Scope

Dieses Dokument ist der formale Security-Sign-off fuer den aktuellen `dev`-Stand von AdminBot v1.0.x.

Geprueft wurden:

- Rust-Code unter `src/`
- versionierte Security-Dokumentation unter `docs/security/`
- Deployment-Artefakte:
  - `adminbotd.service`
  - `config/policy.example.toml`
  - `deploy/polkit/50-adminbotd-systemd.rules`
- Release- und CI-Artefakte:
  - `scripts/verify_security_release_gate.sh`
  - `.github/workflows/security-gate.yml`

Nicht im Scope:

- externe Zielsysteme, die nicht mit dem `live`-Gate geprueft wurden
- generelle Linux-Basis-Haertung ausserhalb von AdminBot
- Supply-Chain- und Build-Server-Themen ausserhalb dieses Repositorys

## 2. Threat-Model-Referenz

Grundlage des Reviews:

- [THREAT_MODEL.md](/home/dev/Documents/Smolit_AdminBot/docs/security/THREAT_MODEL.md)
- [TRUST_BOUNDARIES.md](/home/dev/Documents/Smolit_AdminBot/docs/security/TRUST_BOUNDARIES.md)
- [ATTACK_SURFACES.md](/home/dev/Documents/Smolit_AdminBot/docs/security/ATTACK_SURFACES.md)
- [ABUSE_CASES.md](/home/dev/Documents/Smolit_AdminBot/docs/security/ABUSE_CASES.md)
- [HARDENING_CHECKLIST.md](/home/dev/Documents/Smolit_AdminBot/docs/security/HARDENING_CHECKLIST.md)
- [SECURITY_FIX_ROADMAP_V1X.md](/home/dev/Documents/Smolit_AdminBot/docs/security/SECURITY_FIX_ROADMAP_V1X.md)
- [SECURITY_RELEASE_GATE.md](/home/dev/Documents/Smolit_AdminBot/docs/security/SECURITY_RELEASE_GATE.md)

Wichtige Einordnung:

- Teile der aelteren Threat-/Review-Dokumente beschreiben noch den Vorhaertungsstand vor Abschluss von `#71` bis `#82`.
- Fuer Freigabeentscheidungen gilt dieses Dokument als aktueller Konsolidierungsstand.
- Widerspruechliche Alt-Aussagen aus Baseline-Dokumenten sind historisch zu lesen, nicht als aktueller Systemzustand.

## 3. Implementierte Sicherheitsmassnahmen

### Architektur und Privilegmodell

- non-root Daemon `adminbotd`
- statische Action Registry
- kein Shell-Exec, kein `systemctl`, kein Plugin-System
- privilegierte Service-Steuerung nur ueber `RestartUnit(unit, "replace")`
- polkit ist als schmale Privilegbruecke versioniert und dokumentiert

### IPC / Boundary Hardening

- harte IPC-Frame-Grenze: `64 KiB`
- Socket-Read-Timeout: `1000 ms`
- Socket-Write-Timeout: `1000 ms`
- lokale Admission-Control: `8` Verbindungen pro `1000 ms`
- fail-closed fuer unsichere Runtime- und Socket-Artefakte
- Peer-Credentials via `SO_PEERCRED`

### Identitaet / Autorisierung

- Autorisierung folgt Unix-User-/Unix-Group-Mapping, nicht `requested_by.*`
- `allowed_request_types` wird fuer Autorisierung nicht akzeptiert
- `max_parallel_mutations` wird technisch erzwungen
- Policy-Datei wird beim Start fail-closed validiert:
  - regulaeres File
  - root-owned
  - nicht group-writable
  - nicht world-writable

### Service Control

- Unit-Whitelist
- Cooldown pro Unit
- Rate-Limit pro Stunde
- Pre- und Post-Status-Pruefung
- systemd/polkit-Integrationsnachweis fuer den echten Restart-Pfad ist vorhanden

### Audit / Logging / Journald

- Request-Lifecycle wird strukturiert auditiert
- echte Peer-UID/GID/PID werden geloggt
- Policy- und Capability-Entscheidungen werden geloggt
- repetitive Boundary-Fehler werden auditseitig begrenzt:
  - Burst-Limit `4 / 1000 ms`
  - einmaliger Suppressionsmarker
- `journal.query` ist gegen grosse Antworten begrenzt:
  - max. `2048` Bytes pro `MESSAGE`
  - max. `32768` Bytes Gesamtantwort

### Deployment / Release Enforcement

- versionierte polkit-Regelvorlage im Repo
- versionierte `adminbotd.service`
- Security Release Gate Script mit `artifact`- und `live`-Modus
- GitHub Actions Workflow `security-gate` erzwingt das `artifact`-Gate auf PRs sowie Pushes nach `dev` und `main`

## 4. Verifikationsergebnis

Folgende Checks wurden fuer diesen Sign-off erneut nachvollzogen:

- `cargo build` -> gruen
- `cargo test` -> gruen
- `bash scripts/verify_security_release_gate.sh --mode artifact` -> `PASS`
- kontrollierte Fehlkonfiguration:
  - modifizierte Policy mit `max_parallel_mutations = 2`
  - `bash scripts/verify_security_release_gate.sh --mode artifact --policy <broken-copy>` -> `FAIL`
- `systemd-analyze security --offline=yes ./adminbotd.service` -> `Overall exposure level ... 4.7 OK`
- `systemd-analyze verify ./adminbotd.service` -> kein lokaler Verify-Fehler auf dem aktuellen Host

Bewertung:

- das Repository erzwingt die definierten P0/P1-Artefaktgrenzen reproduzierbar
- der Gate-Check ist wirksam und nicht nur dokumentiert
- die Hardening-Basis ist belastbar, aber nicht maximal

## 5. Offene Risiken

Diese Risiken sind nach aktuellem Stand real, aber keine P0/P1-Release-Blocker mehr:

1. Replay- und Idempotenzstrategie fuer mutierende Requests ist noch nicht implementiert.
2. Restart-Abuse-Counter sind nicht persistent ueber Daemon-Neustarts.
3. Weitere systemd-Hardening-Optionen wie `SystemCallFilter`, `ProtectKernel*`, `ProtectProc`, `UMask` sind noch offen.
4. Audit-Aufbewahrung, Integritaetsprozess und Journald-Exposure sind betrieblich noch nicht voll formalisiert.
5. Read-only Actions bleiben bei zu breiter Policy sensibel, vor allem `journal.query` und `process.snapshot`.
6. Es gibt keinen zweiten robusten Audit-Sink neben journald/stderr.

## 6. Notwendige Deployment-Voraussetzungen

AdminBot ist nur unter diesen Bedingungen als hoch sicher produktionsreif freigegeben:

1. `adminbotd` laeuft als Unix-User `adminbot`, nicht als Root.
2. `adminbotd.service` wird in der versionierten Form oder strenger installiert.
3. `/etc/adminbot/policy.toml` ist root-owned, nicht group-/world-writable und fachlich least-privilege konfiguriert.
4. `/run/adminbot` ist ein echtes Verzeichnis mit Owner/Group `adminbot:adminbot` und Modus `0750`.
5. `/run/adminbot/adminbot.sock` ist ein echter Unix-Socket mit Owner `adminbot`, Gruppe `adminbotctl` und Modus `0660`.
6. Die installierte polkit-Regel entspricht inhaltlich der versionierten Vorlage und wird nicht durch breitere lokale Regeln unterlaufen.
7. Human- und Agent-Rollen werden ueber getrennte Unix-Identitaeten oder Unix-Gruppen getrennt, nicht ueber `requested_by.type`.
8. Human- und Agent-Policy-Matches bleiben nicht ueberlappend, wenn unterschiedliche Rechte beabsichtigt sind; gemeinsame Socket-Zugriffsgruppen duerfen nicht zugleich breitere Human-Capabilities vergeben.
9. Vor jedem Release und jedem Zielsystem-Rollout werden beide Gates genutzt:
   - `artifact`
   - `live`
10. Der ignored Integrationstest fuer `service.restart` wird auf dem Zielsystem mit sicherer Test-Unit erneut nachgewiesen, wenn polkit-, systemd- oder Deploy-Artefakte geaendert wurden.
11. Die Agent-NN-Integration folgt den Dokumenten unter `docs/integrations/` und fuehrt keine zweite lokale Sicherheitslogik ein.

## 7. Minimale Deployment-Checkliste fuer Betreiber

### Vor Installation

- Unix-User `adminbot` existiert
- Gruppe `adminbotctl` existiert
- Zielsystem nutzt systemd und polkit
- `/usr/local/bin/adminbotd` ist installiert

### Artefakte installieren

- `adminbotd.service` nach `/etc/systemd/system/adminbotd.service`
- polkit-Regel nach `/etc/polkit-1/rules.d/50-adminbotd-systemd.rules`
- Policy nach `/etc/adminbot/policy.toml`

### Rechte setzen

- `/etc/adminbot/policy.toml` -> `root:root`, nicht group-/world-writable
- `/run/adminbot` -> `adminbot:adminbot`, `0750`
- Socket-Gruppe fuer Clients -> `adminbotctl`

### Vor Produktivstart pruefen

- `bash scripts/verify_security_release_gate.sh --mode artifact`
- `bash scripts/verify_security_release_gate.sh --mode live`
- `systemd-analyze security --offline=yes ./adminbotd.service`
- ignored Integrationsnachweis fuer `service.restart` auf sicherer Test-Unit

### Betriebsregeln

- `read_sensitive` nur restriktiv vergeben
- `service_control` nur fuer klar begrenzte lokale Admin-Identitaeten vergeben
- keine zusaetzlichen breiten polkit-Regeln fuer systemd-Management pflegen
- Drift in Policy, polkit oder Unit-Datei als Security-Event behandeln

## 8. Realistischster Angriffsweg nach aktueller Haertung

Der realistischste Angriffspunkt ist nicht mehr die IPC-Grenze selbst, sondern Betriebs- und Rollenkonfiguration:

- zu breite `read_sensitive`-Freigaben koennen weiterhin Diagnose- und Journaldaten offenlegen
- gemeinsame Unix-Identitaeten fuer Human und Agent wueren die gewollte Trust-Grenze aufweichen
- ueberlappende Human- und Agent-Policy-Matches koennen Capabilities ungeplant vereinigen
- breitere lokale polkit-Regeln ausserhalb des Repo koennen die saubere D-Bus-Grenze unterlaufen

Der gefaehrlichste verbleibende technische Missbrauchspfad ist derzeit:

- legitimer lokaler Client mit zu viel Policy-Reichweite, nicht ein einfacher roher IPC-DoS

## 9. Sign-Off Bewertung

### Urteil

Ja. AdminBot v1.0.x kann als **hoch sicher produktionsreif unter den oben genannten Bedingungen** freigegeben werden.

### Begruendung

- alle P0- und P1-Haertungen aus `#71` bis `#82` sind technisch umgesetzt
- Code, Deployment-Artefakte, Gate-Script und CI sind konsistent genug fuer eine belastbare Freigabe
- die verbleibenden offenen Risiken liegen in `P2`/`P3` und in betrieblicher Disziplin, nicht mehr in offenen P0/P1-Grenzen

### Grenzen des Sign-offs

Dieses Urteil gilt nicht pauschal fuer beliebige Zielsysteme. Es gilt nur, wenn:

- das `live`-Gate auf dem Zielsystem gruen ist
- die reale polkit- und systemd-Installation der versionierten Erwartung entspricht
- Betreiber die Rollentrennung und Least-Privilege-Policy tatsaechlich einhalten

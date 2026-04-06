# AdminBot Security Decisions v1.0.x

## Zweck

Dieses Dokument haelt die sicherheitsrelevanten Entscheidungen fuer die Nachhaertung von AdminBot v1.0.x fest. Es beschreibt keine Implementierung im Detail, sondern verbindliche Leitplanken fuer die naechsten Sicherheitsphasen.

## Entscheidung 1: Maximale IPC-Frame-Groesse wird verpflichtend

- Prioritaet: `P0`
- GitHub-Issue: `#71`
- Entscheidung: eingehende IPC-Frames erhalten eine harte technische Obergrenze von `64 KiB`.
- Begruendung: ohne Obergrenze bleibt die lokale IPC-Grenze fuer Speicher- und DoS-Angriffe zu offen.
- Nicht Ziel: generische Streaming-API oder Protokollumbau.

## Entscheidung 2: Socket-Read-Timeouts werden verpflichtend

- Prioritaet: `P0`
- GitHub-Issue: `#72`
- Entscheidung: der Daemon darf langsame Clients nicht unbegrenzt bedienen und setzt einen konservativen IPC-Read-Timeout von `1000 ms`.
- Begruendung: Slow-Client-DoS ist bei sequentieller Verarbeitung ein realistisches lokales Risiko.
- Nicht Ziel: parallele Komplettarchitektur in diesem Schritt.

## Entscheidung 3: Socket-Write-Timeouts werden verpflichtend

- Prioritaet: `P0`
- GitHub-Issue: `#73`
- Entscheidung: Antwortpfade duerfen nicht unbegrenzt auf blockierende Clients warten und setzen einen konservativen IPC-Write-Timeout von `1000 ms`.
- Begruendung: Verfuegbarkeits- und Rueckstau-Risiko am IPC-Ausgangspfad.
- Nicht Ziel: neuer Transport oder asynchrones Komplettmodell.

## Entscheidung 4: Lokale Admission-Control wird eingefuehrt

- Prioritaet: `P0`
- GitHub-Issue: `#74`
- Entscheidung: AdminBot fuehrt eine kleine lokale Burst-Grenze von `8 Verbindungen pro 1000 ms` vor weiterer Request-Verarbeitung ein.
- Begruendung: reine Eingabevalidierung reicht gegen Flooding nicht aus.
- Nicht Ziel: globales verteiltes Rate-Limiting.

## Entscheidung 5: `requested_by` ist ohne Peer-Bindung nicht sicherheitsrelevant

- Prioritaet: `P0`
- GitHub-Issue: `#75`
- Entscheidung: selbstdeklarierte Request-Metadaten duerfen keine eigenstaendige Security-Semantik tragen, wenn sie nicht an echte Peer-Credentials gebunden sind. `requested_by.type` und `requested_by.id` bleiben Audit- und Korrelation-Metadaten; Capability-Entscheidungen folgen nur dem Peer-Match ueber `unix_user` und `unix_group`.
- Begruendung: Identitaets- und Capability-Entscheidungen muessen auf belastbaren lokalen Identitaetsdaten beruhen.
- Nicht Ziel: externe Authentifizierungsinfrastruktur oder Netzwerk-Identity-Layer.
- Zusatzregel: `allowed_request_types` wird in v1.x nicht mehr fuer Autorisierung akzeptiert; getrennte Human-/Agent-Rollen muessen ueber getrennte Unix-Identitaeten oder Gruppen modelliert werden.

## Entscheidung 6: Policy-Dateirechte werden beim Start validiert

- Prioritaet: `P0`
- GitHub-Issue: `#76`
- Entscheidung: `/etc/adminbot/policy.toml` wird als sicherheitskritisches Artefakt behandelt und bei ungueltigem Owner oder Modus abgelehnt. Erwartet wird root-owned sowie weder group- noch world-writable.
- Begruendung: Policy-Manipulation unterlaeuft die zentrale Sicherheitsgrenze von AdminBot.
- Nicht Ziel: komplexes Secret-Management-System.

## Entscheidung 7: polkit-Regeln sind versionierte Security-Artefakte

- Prioritaet: `P0`
- GitHub-Issue: `#77`
- Entscheidung: polkit-Regeln werden versioniert, dokumentiert und als Teil des Security-Reviews behandelt. Die v1.x-Vorlage erlaubt nur `org.freedesktop.systemd1.manage-units` fuer den Service-User `adminbot`.
- Begruendung: die D-Bus/polkit-Bruecke ist die reale Privileggrenze fuer mutierende Service-Aktionen.
- Nicht Ziel: Ersatz von polkit durch eigene Privilegmechanismen.

## Entscheidung 8: `max_parallel_mutations` wird technisch erzwungen

- Prioritaet: `P1`
- GitHub-Issue: `#78`
- Entscheidung: modellierte Mutationsgrenzen muessen in der Laufzeit Wirkung entfalten. `max_parallel_mutations` wird fuer mutierende Non-Dry-Run-Requests fail-fast mit `rate_limited` erzwungen.
- Begruendung: Sicherheitsmodelle ohne technische Erzwingung sind fuer Missbrauchskontrolle zu schwach.
- Nicht Ziel: aggressive Parallelisierung der gesamten Architektur.

## Entscheidung 9: Audit-Flood-Schutz wird ausgebaut

- Prioritaet: `P1`
- GitHub-Issue: `#79`
- Entscheidung: wiederholte invalide oder missbrauchsartige Requests duerfen den Audit-Kanal nicht dominieren. Repetitive Boundary-Fehler (`validation_error`, `unsupported_version`, `unauthorized`, `forbidden`) werden deshalb pro Peer/Action in einem festen Fenster von `1000 ms` nach `4` Audit-Emissionen gedrosselt; beim Eintritt in die Unterdrueckung wird genau ein Suppressionshinweis emittiert.
- Begruendung: Sichtbarkeit fuer echte Vorfaelle darf nicht durch triviales Flooding verloren gehen.
- Nicht Ziel: Entfernung sicherheitsrelevanter Audit-Daten.

## Entscheidung 10: Journald-Ausgabegroessen erhalten Guardrails

- Prioritaet: `P1`
- GitHub-Issue: `#80`
- Entscheidung: Read-only Datenpfade muessen auch globale Groessen- und Exfiltrationsgrenzen beachten. `journal.query` clippt einzelne Journalnachrichten deshalb auf `2048 Bytes` und begrenzt die gesamte JSON-Antwort deterministisch auf `32768 Bytes`.
- Begruendung: Count- und Zeitfenstergrenzen allein reduzieren Informationsabfluss nicht ausreichend.
- Nicht Ziel: generische Inhaltsklassifikation fuer alle Logs in derselben Phase.

## Entscheidung 11: Runtime- und Socket-Invarianten werden beim Start validiert

- Prioritaet: `P1`
- GitHub-Issue: `#81`
- Entscheidung: `/run/adminbot`, Socket-Datei und zugehoerige Besitz-/Modusannahmen werden beim Start fail closed geprueft. Erwartet werden ein echtes Runtime-Verzeichnis mit Modus `0750`, ein Unix-Socket mit Modus `0660` sowie keine unsicheren Alt-Artefakte am Socket-Pfad.
- Begruendung: lokale IPC-Sicherheit ist stark vom korrekten Deployment der Laufzeitartefakte abhaengig.
- Nicht Ziel: Ersatz von systemd fuer Socket-Management.

## Entscheidung 12: Release-Freigaben enthalten ein Security-Gate

- Prioritaet: `P1`
- GitHub-Issue: `#82`
- Entscheidung: Release und produktives Deployment gelten erst nach expliziter Pruefung von Policy, polkit, Hardening und Zielsystem-Nachweisen als freigabefaehig. Der verbindliche Gate-Check liegt als Script unter `scripts/verify_security_release_gate.sh` vor und deckt einen Repo-Artefakt-Modus sowie einen Live-Deployment-Modus ab.
- Begruendung: ein sicherer Codepfad ist wertlos, wenn die Betriebsartefakte driften oder unreviewt ausgerollt werden.
- Nicht Ziel: vollautomatisierte Compliance-Plattform.

## Entscheidung 13: Replay-Schutz fuer mutierende Requests wird definiert

- Prioritaet: `P2`
- GitHub-Issue: `#83`
- Entscheidung: mutierende Non-Dry-Run-Requests behandeln `request_id` fuer ein peer-gebundenes Fenster von `300 s` als Idempotency-Key. Identische Replays liefern denselben gecachten Response, parallele Duplikate werden retryable mit `rate_limited` abgewiesen und mismatched Wiederverwendung derselben `request_id` wird als `validation_error` verworfen.
- Begruendung: wiederholte lokale Requests koennen trotz Policy und Cooldown operative Nebenwirkungen erzeugen.
- Nicht Ziel: verteilter Exactly-Once-Mechanismus.

## Entscheidung 14: Abuse-Counter duerfen nicht an Daemon-Neustarts scheitern

- Prioritaet: `P2`
- GitHub-Issue: `#84`
- Entscheidung: Restart-Abuse-Zaehler werden als einzelnes lokales State-Artefakt unter `/var/lib/adminbot/restart_abuse_state.json` persistiert. Das Artefakt muss dem laufenden `adminbotd` gehoeren, regulaer sein und darf weder group- noch world-accessible sein; wenn Laden oder Persistieren fehlschlaegt, wird `service.restart` fail closed blockiert.
- Begruendung: volatile Schutzzaehler sind fuer laenger laufende Systeme schwach.
- Nicht Ziel: komplexe persistente Telemetrieplattform.

## Entscheidung 15: systemd-Haertung wird ueber die Baseline hinaus erweitert

- Prioritaet: `P2`
- GitHub-Issue: `#85`
- Entscheidung: die versionierte `adminbotd.service` wird ueber die Baseline hinaus mit `UMask=0077`, `ProtectClock=true`, `ProtectHostname=true`, `ProtectControlGroups=true`, `ProtectKernelTunables=true`, `ProtectKernelModules=true`, `ProtectKernelLogs=true`, `RestrictSUIDSGID=true`, `RestrictNamespaces=true`, `SystemCallArchitectures=native` und `RemoveIPC=true` gehaertet. Diese Flags werden zugleich Teil des verbindlichen Security Release Gates.
- Begruendung: die aktuelle Baseline ist gut, aber noch nicht maximal reduziert.
- Nicht Ziel: blinde Aktivierung aller systemd-Optionen ohne Funktionspruefung, insbesondere `ProtectProc=` und `SystemCallFilter=` ohne gesonderten Betriebsnachweis.

## Entscheidung 16: Audit-Retention und Journald-Exposure werden betrieblich definiert

- Prioritaet: `P2`
- GitHub-Issue: `#86`
- Entscheidung: Audit-Sichtbarkeit, Aufbewahrung und Expositionsgrenzen werden als Betriebsprozess dokumentiert.
- Begruendung: Incident Response braucht reproduzierbare und sichere Audit-Betriebsregeln.
- Nicht Ziel: Aufbau eines separaten SIEM-Produkts im selben Schritt.

## Entscheidung 17: Read-only Actions erhalten Security-Klassifikation

- Prioritaet: `P3`
- GitHub-Issue: `#87`
- Entscheidung: Read-only Actions werden nicht pauschal als harmlos betrachtet, sondern nach Sensitivitaet klassifiziert.
- Begruendung: Informationen ueber Journald, Services, Dateisystem und Systemzustand koennen fuer Spaehung oder Planung missbraucht werden.
- Nicht Ziel: sofortige funktionale Beschneidung aller Read-only Actions.

## Produktionsfreigabe-Leitlinie

AdminBot gilt erst dann als "hoch sicher fuer produktiven Einsatz", wenn mindestens folgende Entscheidungen umgesetzt und betrieblich verifiziert sind:

- Entscheidung 1 bis 7
- gehärtete `adminbotd.service` auf dem Zielsystem aktiv
- versionierte und gepruefte polkit-Regeln
- root-kontrollierte und validierte Policy-Datei
- validierte Runtime- und Socket-Rechte

## Annahmen

- Das Grunddesign mit non-root Daemon, Unix Socket, statischer Registry und D-Bus/polkit bleibt bestehen.
- Die Nachhaertung erfolgt ohne Shell-Exec, ohne Plugin-System und ohne neue generische Privilegpfade.

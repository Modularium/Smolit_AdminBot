# AdminBot v2 Hardening Checklist

## Deployment und Service

[x] `adminbotd` laeuft als non-root Benutzer
[x] `adminbotd.service` nutzt `NoNewPrivileges=true`
[x] `adminbotd.service` nutzt `PrivateTmp=true`
[x] `adminbotd.service` nutzt `PrivateDevices=true`
[x] `adminbotd.service` nutzt `ProtectSystem=strict`
[x] `adminbotd.service` nutzt `ProtectHome=true`
[x] `adminbotd.service` nutzt `MemoryDenyWriteExecute=true`
[x] `adminbotd.service` nutzt `RestrictRealtime=true`
[x] `adminbotd.service` nutzt `LockPersonality=true`
[x] `adminbotd.service` nutzt leeres `CapabilityBoundingSet=`
[x] `adminbotd.service` nutzt `RestrictAddressFamilies=AF_UNIX`
[ ] `UMask=` fuer erzeugte Dateien und Sockets explizit festlegen
[ ] `ProtectKernelTunables=` pruefen und falls moeglich aktivieren
[ ] `ProtectKernelModules=` pruefen und falls moeglich aktivieren
[ ] `ProtectKernelLogs=` pruefen und falls moeglich aktivieren
[ ] `RestrictSUIDSGID=` pruefen und falls moeglich aktivieren
[ ] `ProtectProc=` und `ProcSubset=` pruefen
[ ] `SystemCallFilter=` konservativ definieren
[ ] `IPAddressDeny=` oder gleichwertige Netzrestriktion explizit pruefen
[ ] `RemoveIPC=` und weitere Namespace-Restriktionen bewerten

## IPC und Request-Handling

[x] Socket ist lokal und Unix Domain Socket
[x] Socket-Modus ist `0660`
[x] Socket-Gruppenzuordnung auf `adminbotctl` ist vorgesehen
[x] Runtime-Verzeichnis `/run/adminbot` wird mit erwarteten Invarianten geprueft: real directory, Owner `adminbot`, Gruppe `adminbot`, Modus `0750`
[x] unsichere Alt-Artefakte am Socket-Pfad blockieren den Start fail closed
[x] Peer-Credentials werden ueber `SO_PEERCRED` gelesen
[x] Requests sind versioniert
[x] unbekannte Felder werden in Kernstrukturen abgewiesen
[x] `request_id` muss UUID sein
[x] maximale IPC-Frame-Groesse auf `64 KiB` definieren und technisch erzwingen
[x] Socket-Read-Timeouts mit konservativem Default von `1000 ms` definieren
[x] Socket-Write-Timeouts mit konservativem Default von `1000 ms` definieren
[ ] Schutz gegen Slow-Client-Blockade definieren
[x] lokale Admission-Control gegen Burst-Flooding mit Fenster `8 Verbindungen / 1000 ms` aktivieren
[ ] Replay-Schutz fuer mutierende Requests explizit bewerten
[x] `requested_by.type` und `requested_by.id` nur noch als Audit-/Korrelation-Metadaten behandeln; Autorisierung folgt Peer-UID/GID und Policy-Match

## Policy und Autorisierung

[x] Policy nutzt versioniertes TOML
[x] unbekannte Policy-Felder werden abgewiesen
[x] Actions werden ueber Positivliste freigegeben
[x] Capabilities werden zentral geprueft
[x] Mount-Whitelist existiert
[x] Service-Unit-Whitelist existiert
[x] Restart-Cooldown existiert
[x] Restart-Rate-Limit existiert
[x] Eigentuemer und Modus von `/etc/adminbot/policy.toml` beim Start hart pruefen: root-owned, nicht group-writable, nicht world-writable
[ ] Policy-Integritaet oder Change-Control dokumentieren
[x] `allowed_request_types` nicht mehr fuer Autorisierung verwenden; getrennte Unix-User oder -Gruppen fuer getrennte Rollen erzwingen
[x] `max_parallel_mutations` aktiv technisch erzwingen; mutierende Non-Dry-Run-Requests werden ueber dem Policy-Limit fail-fast mit `rate_limited` abgewiesen

## Action- und Backend-Sicherheit

[x] statische Action Registry statt generischer Shell
[x] `service.restart` nutzt ausschliesslich `RestartUnit(unit, "replace")`
[x] kein `systemctl`
[x] kein Shell-Fallback
[x] Unit-Namen werden strikt validiert
[x] Journal-Queries sind begrenzt nach Count und Zeitfenster
[x] Journal-Queries clippen einzelne `MESSAGE`-Felder auf `2048 Bytes` und begrenzen die gesamte JSON-Antwort deterministisch auf `32768 Bytes`
[ ] Sensitivitaet von Read-only Endpoints pro Deployment explizit freigeben
[ ] D-Bus- und journald-Ausfallpfade betrieblich absichern

## Logging und Audit

[x] eingehende Requests werden auditiert
[x] erfolgreiche Requests werden auditiert
[x] Fehler werden auditiert
[x] Peer UID, GID und PID werden geloggt
[x] Policy- und Capability-Entscheidungen werden geloggt
[x] stderr-Fallback fuer Audit existiert
[x] repetitive Boundary-Fehler (`validation_error`, `unsupported_version`, `unauthorized`, `forbidden`) werden pro Peer/Action mit Burst-Limit `4 / 1000 ms` auditseitig gedrosselt; ein Suppressionsmarker wird einmalig emittiert
[ ] Aufbewahrung und Integritaet der Audit-Daten betrieblich definieren
[x] Audit-Flooding fuer repetitive invalide Requests ist mit deterministischem Drosselungsfenster bewertet und technisch begrenzt
[ ] sensible Inhalte in Audit und `journal.query` auf Redaktionsbedarf pruefen

## polkit und Systemintegration

[x] polkit-Regeln als versioniertes Betriebsartefakt dokumentieren
[ ] polkit-Regeln auf minimale Identitaeten und minimale Aktionen verengen
[ ] sicherstellen, dass polkit nicht mehr erlaubt als die lokale Policy
[ ] Zielsystem-Validierung nach jeder relevanten Härtungsanpassung wiederholen

## Test und Review

[x] lokaler Testbestand fuer Validierung und Policy ist vorhanden
[x] Integrationstest fuer echten Restart-Pfad existiert als opt-in ignored test
[x] Security-Release-Gate-Script fuer Repo-Artefakte und Live-Deployment ist vorhanden
[x] GitHub Actions erzwingt das `artifact`-Security-Gate fuer Pull Requests sowie Pushes auf `dev` und `main`
[ ] manuelle Zielsystem-Pruefung fuer Hardening regelmaessig wiederholen

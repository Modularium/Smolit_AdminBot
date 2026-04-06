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
[x] Peer-Credentials werden ueber `SO_PEERCRED` gelesen
[x] Requests sind versioniert
[x] unbekannte Felder werden in Kernstrukturen abgewiesen
[x] `request_id` muss UUID sein
[x] maximale IPC-Frame-Groesse auf `64 KiB` definieren und technisch erzwingen
[ ] Socket-Read-Timeouts definieren
[ ] Socket-Write-Timeouts definieren
[ ] Schutz gegen Slow-Client-Blockade definieren
[ ] Request-Flooding und lokale Admission-Control bewerten
[ ] Replay-Schutz fuer mutierende Requests explizit bewerten
[ ] `requested_by` staerker an echte lokale Identitaet binden

## Policy und Autorisierung

[x] Policy nutzt versioniertes TOML
[x] unbekannte Policy-Felder werden abgewiesen
[x] Actions werden ueber Positivliste freigegeben
[x] Capabilities werden zentral geprueft
[x] Mount-Whitelist existiert
[x] Service-Unit-Whitelist existiert
[x] Restart-Cooldown existiert
[x] Restart-Rate-Limit existiert
[ ] Eigentuemer und Modus von `/etc/adminbot/policy.toml` beim Deployment hart pruefen
[ ] Policy-Integritaet oder Change-Control dokumentieren
[ ] `allowed_request_types` nur mit starker Client-Identitaetsbindung verwenden
[ ] `max_parallel_mutations` aktiv technisch erzwingen

## Action- und Backend-Sicherheit

[x] statische Action Registry statt generischer Shell
[x] `service.restart` nutzt ausschliesslich `RestartUnit(unit, "replace")`
[x] kein `systemctl`
[x] kein Shell-Fallback
[x] Unit-Namen werden strikt validiert
[x] Journal-Queries sind begrenzt nach Count und Zeitfenster
[ ] globale Groessenbegrenzung fuer ausgehende Journal-Daten bewerten
[ ] Sensitivitaet von Read-only Endpoints pro Deployment explizit freigeben
[ ] D-Bus- und journald-Ausfallpfade betrieblich absichern

## Logging und Audit

[x] eingehende Requests werden auditiert
[x] erfolgreiche Requests werden auditiert
[x] Fehler werden auditiert
[x] Peer UID, GID und PID werden geloggt
[x] Policy- und Capability-Entscheidungen werden geloggt
[x] stderr-Fallback fuer Audit existiert
[ ] Aufbewahrung und Integritaet der Audit-Daten betrieblich definieren
[ ] Audit-Flooding und Log-Rotation bewerten
[ ] sensible Inhalte in Audit und `journal.query` auf Redaktionsbedarf pruefen

## polkit und Systemintegration

[ ] polkit-Regeln als versioniertes Betriebsartefakt dokumentieren
[ ] polkit-Regeln auf minimale Identitaeten und minimale Aktionen verengen
[ ] sicherstellen, dass polkit nicht mehr erlaubt als die lokale Policy
[ ] Zielsystem-Validierung nach jeder relevanten Härtungsanpassung wiederholen

## Test und Review

[x] lokaler Testbestand fuer Validierung und Policy ist vorhanden
[x] Integrationstest fuer echten Restart-Pfad existiert als opt-in ignored test
[ ] Security-Regression-Checkliste in Release-Prozess aufnehmen
[ ] manuelle Zielsystem-Pruefung fuer Hardening regelmaessig wiederholen

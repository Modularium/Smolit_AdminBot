# Worklog Architekturphase

## Verwendete Grundlagen

Als Hauptgrundlage wurden verwendet:

- `/home/dev/Agent-NN/docs/adminbot_adminnn_ist-analyse.md`
- `/home/dev/Agent-NN/docs/adminbot_adminnn_review_worklog.md`

Diese Berichte wurden nicht neu erhoben, sondern in eine implementierungsnahe Zielarchitektur überführt.

## Getroffene Entscheidungen in dieser Finalisierungsphase

- `adminbotd` bleibt non-root
- Root ist Eigenschaft einzelner Aktionen, nicht des Gesamtprozesses
- `service.restart` wird in `v1` primär über systemd D-Bus plus polkit umgesetzt
- `service.restart` ist für `v1` konkret auf `org.freedesktop.systemd1.Manager.RestartUnit(unit, "replace")` festgelegt
- AdminBot-Mode ist in `v1` nur `safe`
- dedizierter Root-Helper ist nur Reserveoption, nicht Standardpfad
- Linux Capabilities sind nicht der Primärweg für Service-Control
- Policy-Modell `v1` wird als statisches TOML festgelegt
- IPC wird final auf Unix Domain Socket plus JSON plus length-prefixed Framing festgelegt
- IPC-Versionierung wird verbindlich als Integer `version: 1` geführt
- globales IPC-Fehlermodell mit stabilem `error.code`-Vertrag ist festgelegt
- `v1` bleibt klein
- `service.start` und `service.stop` sind nicht Teil von `v1`
- `Agent-NN` nutzt später dedizierte Tools über einen dedizierten Worker-/Servicepfad
- `Agent-NN` erhält in `v1` standardmäßig keine `service_control`-Capability
- `RestrictAddressFamilies=AF_UNIX` bleibt Zielwert und ist expliziter Verifikationspunkt

## Aufgelöste offene Punkte

Folgende zuvor offene Fragen wurden entschieden:

- technische Umsetzung privilegierter Service-Steuerung:
  - entschieden zugunsten von systemd D-Bus plus polkit
- konkrete Restart-Semantik:
  - entschieden auf `RestartUnit` mit Mode `"replace"` und synchronem Post-Check
- Policy-Syntax:
  - entschieden zugunsten von kleinem TOML
- IPC-Versionierung:
  - entschieden zugunsten von Integer `version: 1`
- IPC-Fehlermodell:
  - auf feste Fehlerstruktur und stabile v1-Fehlercodes festgelegt
- `service.start` und `service.stop`:
  - explizit aus `v1` ausgeschlossen

## Verbleibende Risiken

- genaue D-Bus/polkit-Integration muss in der Implementierungsphase distributionstauglich getestet werden
- die initiale Whitelist erlaubter Units muss bewusst klein definiert werden
- journald- und systemd-nahe Lesepfade müssen auf Zielsystemen ohne unnötige Rechte sauber verifiziert werden
- falls einzelne Zielsysteme D-Bus/polkit nicht belastbar bereitstellen, muss die Reserveoption Root-Helper erneut überprüft werden
- `RestrictAddressFamilies=AF_UNIX` muss praktisch gegen systemd D-Bus und polkit verifiziert werden

## Nächste Schritte Richtung Implementierung

1. Implementierungsplan aus diesen Dokumenten ableiten
2. Policy- und Config-Modelle als Rust-Typen planen
3. IPC-Protokoll und Framing zuerst umsetzen
4. read-only Actions vor mutierenden Actions implementieren
5. `service.restart` erst nach funktionsfähigem Audit-, Policy- und Dry-Run-Pfad implementieren
6. systemd D-Bus plus polkit für kleine Unit-Whitelist integrieren
7. globale Fehlercodes und Response-Typen zuerst als Rust-Modelle fixieren
8. AF_UNIX-Hardening gegen den realen D-Bus/polkit-Pfad testen

## Ergebnischarakter

Diese Phase liefert keine Implementierung, aber jetzt eine implementierungsreife Grundlage für die nächste Phase. Die kritischen Architekturfragen sind entschieden, der `v1`-Scope ist begrenzt und die Root-/Privilegstrategie ist mit IPC, Policy und Action Registry abgestimmt. Offene Punkte sind keine Architekturstreitfragen mehr, sondern gezielte Implementierungs- und Verifikationsthemen.

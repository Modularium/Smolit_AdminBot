# AdminBot polkit Security Artifact

## Status

Das Repository versioniert ab v1.0.x eine explizite polkit-Regelvorlage unter:

- `deploy/polkit/50-adminbotd-systemd.rules`

## Sicherheitszweck

Die Regel macht die vorher unsichtbare Betriebsabhaengigkeit fuer `service.restart` reviewbar.

Sie dient ausschliesslich dazu, `adminbotd` den minimal benoetigten systemd-polkit-Aktionspfad zu oeffnen:

- `org.freedesktop.systemd1.manage-units`

## Minimale Freigabe

Die Vorlage erlaubt nur:

- `subject.user == "adminbot"`

Sie erlaubt bewusst **nicht**:

- direkte Endbenutzer
- `adminbotctl`
- beliebige Root-nahe oder generische Service-Identitaeten

## Beziehung zur lokalen Policy

polkit ist schmaler Systemzugang, nicht die fachliche Autorisierung.

Zwingend weiterhin in AdminBot selbst:

- statische Action Registry
- Capability-Pruefung
- Unit-Allowlist
- Cooldown
- Rate-Limit
- D-Bus-Aufruf nur `RestartUnit(unit, "replace")`

Wenn polkit breiter ist als die lokale AdminBot-Policy, bleibt das ein Sicherheitsrisiko. Die Vorlage dokumentiert dieses Restrisiko explizit und macht es reviewbar.

## Deployment-Regel

Produktive Deployments muessen:

1. die versionierte Vorlage aus dem Repository als Ausgangspunkt verwenden
2. keine breitere parallele polkit-Regel fuer `manage-units` aktiv haben
3. nach jeder Aenderung den echten `service.restart`-Pfad erneut validieren

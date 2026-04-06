# AdminBot polkit Artifact

## Zweck

Dieses Verzeichnis versioniert die minimale polkit-Regel fuer den `service.restart`-Pfad von `adminbotd`.

AdminBot nutzt fuer mutierende Service-Steuerung ausschliesslich:

- D-Bus Service: `org.freedesktop.systemd1`
- Methode: `RestartUnit`
- AdminBot-Mode: `safe`
- systemd-Mode: `"replace"`

Die dazugehoerige polkit-Aktion des Zielsystems ist:

- `org.freedesktop.systemd1.manage-units`

## Wichtige Grenze

polkit ist nur die Privilegbruecke.

polkit ersetzt **nicht**:

- die lokale AdminBot-Policy
- Capability-Pruefung
- Unit-Allowlist
- Cooldown
- Rate-Limit

Die fachliche Freigabe bleibt in `adminbotd`.

## Minimale erlaubte Identitaet

Die Vorlage erlaubt nur:

- Unix-User `adminbot`

Bewusst **nicht** erlaubt:

- Endbenutzer
- Gruppe `adminbotctl`
- beliebige Service-Nutzer

## Installationsziel

Die versionierte Vorlage wird auf Zielsystemen unter folgendem Pfad installiert:

- `/etc/polkit-1/rules.d/50-adminbotd-systemd.rules`

## Review-Kriterien

Vor produktivem Einsatz pruefen:

1. die Regel erlaubt nur `org.freedesktop.systemd1.manage-units`
2. die Regel erlaubt nur den Service-User `adminbot`
3. AdminBot-Policy ist enger oder gleich eng wie die polkit-Regel
4. es existiert kein zweiter breiterer lokaler polkit-Pfad fuer dieselbe Funktion
5. Zielsystem-Test fuer `service.restart` lief erfolgreich

## Wichtige Einschraenkung

polkit fuer systemd ist auf Aktions-Ebene grober als AdminBot selbst. Die Unit-Grenze kann in dieser Vorlage nicht enger als `manage-units` modelliert werden. Deshalb muessen:

- die Unit-Whitelist in `policy.toml`
- die feste D-Bus-Methode `RestartUnit`
- die feste Mode-Abbildung `safe -> "replace"`

zwingend erhalten bleiben.

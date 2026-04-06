# AdminBot Security Release Gate

## Zweck

Der Security Release Gate verhindert, dass AdminBot nur auf Code-Ebene sauber wirkt, waehrend sicherheitskritische Deploy-Artefakte driften oder zu breit ausgerollt werden.

Der verbindliche Gate-Check liegt unter:

- `scripts/verify_security_release_gate.sh`

Das Script liefert ausschliesslich klare `PASS`- und `FAIL`-Meldungen und beendet sich bei Findings mit Exit-Code `1`.

## Modi

### `artifact`

Repo- und CI-Modus.

Prueft die versionierten Artefakte im Repository:

- Policy-Beispiel ist vorhanden und enthaelt die erwarteten v1-Constraints
- polkit-Vorlage ist vorhanden und bleibt auf `org.freedesktop.systemd1.manage-units` fuer `adminbot` begrenzt
- `adminbotd.service` enthaelt die verbindlichen Hardening- und Runtime-Zeilen

Aufruf:

```bash
bash scripts/verify_security_release_gate.sh --mode artifact
```

CI-Erzwingung:

- GitHub Actions Workflow: `.github/workflows/security-gate.yml`
- Trigger:
  - jeder `pull_request`
  - jeder Push auf `dev`
  - jeder Push auf `main`
- der Workflow fuehrt verpflichtend `bash scripts/verify_security_release_gate.sh --mode artifact` aus
- ein `FAIL` im Gate macht den Workflow und damit den Build rot

### `live`

Zielsystem-Modus.

Prueft eine installierte Deployment-Umgebung:

- `/etc/adminbot/policy.toml` existiert, ist regulaer, root-owned und nicht group-/world-writable
- die installierte polkit-Regel existiert und entspricht dem versionierten Template
- die installierte `adminbotd.service` enthaelt die erwarteten Hardening-Zeilen
- `/run/adminbot` existiert mit der erwarteten Service-Identitaet und Modus `0750`
- `/run/adminbot/adminbot.sock` existiert als Unix-Socket mit Owner `adminbot`, Gruppe `adminbotctl` und Modus `0660`

Aufruf:

```bash
bash scripts/verify_security_release_gate.sh --mode live
```

## Gepruefte Invarianten

### Policy

- `version = 1`
- `max_parallel_mutations = 1` im Policy-Constraint-Block vorhanden
- im Live-Modus zusaetzlich:
  - root-owned
  - keine group-/world-write-Bits
  - kein Symlink

### polkit

- Aktion bleibt `org.freedesktop.systemd1.manage-units`
- Freigabe bleibt auf `subject.user === "adminbot"` begrenzt
- im Live-Modus muss die installierte Datei dem versionierten Template entsprechen

### systemd Hardening

Mindestens diese Zeilen muessen in `adminbotd.service` vorhanden sein:

- `User=adminbot`
- `Group=adminbot`
- `SupplementaryGroups=adminbotctl`
- `RuntimeDirectory=adminbot`
- `RuntimeDirectoryMode=0750`
- `ExecStart=/usr/local/bin/adminbotd`
- `UMask=0077`
- `NoNewPrivileges=true`
- `PrivateTmp=true`
- `PrivateDevices=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- `ProtectClock=true`
- `ProtectHostname=true`
- `ProtectControlGroups=true`
- `ProtectKernelTunables=true`
- `ProtectKernelModules=true`
- `ProtectKernelLogs=true`
- `MemoryDenyWriteExecute=true`
- `RestrictRealtime=true`
- `RestrictSUIDSGID=true`
- `RestrictNamespaces=true`
- `LockPersonality=true`
- `SystemCallArchitectures=native`
- `CapabilityBoundingSet=`
- `RestrictAddressFamilies=AF_UNIX`
- `RemoveIPC=true`

### Runtime und Socket

Nur im Live-Modus:

- `/run/adminbot` ist ein echtes Verzeichnis
- Owner und Gruppe passen zur Service-Identitaet `adminbot:adminbot`
- Modus ist `0750`
- `/run/adminbot/adminbot.sock` ist ein Unix-Socket
- Owner `adminbot`, Gruppe `adminbotctl`, Modus `0660`

## PASS / FAIL Bedeutung

### PASS

- das gepruefte Artefakt-Set entspricht den erwarteten Security-Invarianten
- der Check ist reproduzierbar und ohne stille Annahmen erfolgreich

### FAIL

- mindestens eine sicherheitsrelevante Invariante ist verletzt
- Release oder Deployment darf nicht als freigabefaehig betrachtet werden

## Sicherer Release-Prozess

Ein Release gilt erst dann als sicher freigabefaehig, wenn beide Stufen erfolgreich waren:

1. `artifact`-Gate gegen die versionierten Repo-Artefakte
2. `live`-Gate auf dem Zielsystem oder im finalen Deployment-Abbild

## CI Integration

Der Repository-Check ist nicht nur lokal verfuegbar, sondern wird zentral ueber GitHub Actions erzwungen.

- Pflicht-Job: `security-gate`
- Script: `bash scripts/verify_security_release_gate.sh --mode artifact`
- Wirkung:
  - Pull Requests muessen das Gate bestehen, bevor sie als sicher reviewbar gelten
  - Pushes auf `dev` und `main` schlagen sichtbar fehl, wenn Policy-, polkit- oder Hardening-Artefakte driften

Der CI-Job ersetzt den `live`-Check nicht. Er stellt nur sicher, dass versionierte Security-Artefakte nicht stillschweigend regressieren.

Der Gate-Check ersetzt nicht:

- den echten ignored Integrationstest fuer `service.restart`
- Review der lokalen Policy
- Review der Zielsystem-polkit-Regeln

Er stellt aber sicher, dass die minimalen Security-Artefakte nicht stillschweigend driften.

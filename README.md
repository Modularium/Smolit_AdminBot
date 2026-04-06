# AdminBot v2

Minimaler Rust-Startpunkt für `AdminBot v2` als lokaler, deterministischer Linux-Daemon.

Aktueller Stand:

- Unix Domain Socket IPC mit `u32`-Length-Prefix und JSON
- typisierte Requests, Responses und Fehlercodes
- statische Action Registry
- minimale Policy Engine auf TOML-Basis
- Audit-Logging über strukturierte Prozessausgabe für journald-Capture
- implementierte Aktionen:
  - `system.status`
  - `system.health`
  - `resource.snapshot`
  - `disk.usage`
  - `service.status`
  - `service.restart`

## Build

```bash
cargo build
```

## Policy vorbereiten

```bash
sudo install -d -m 0755 /etc/adminbot
sudo install -m 0644 config/policy.example.toml /etc/adminbot/policy.toml
sudo chown root:root /etc/adminbot/policy.toml
```

Die Beispielpolicy ist bewusst konservativ und gibt dem lokalen Beispielclient nur Read-only-Capabilities.

`adminbotd` startet fail closed, wenn `/etc/adminbot/policy.toml` nicht root-owned ist oder group-/world-writable bleibt.

## polkit-Artefakt

Die versionierte polkit-Regelvorlage fuer den `service.restart`-Pfad liegt unter:

- `deploy/polkit/50-adminbotd-systemd.rules`

Sie ist bewusst nur fuer den Service-User `adminbot` ausgelegt und oeffnet ausschliesslich die systemd-Aktion `org.freedesktop.systemd1.manage-units`. Die fachliche Freigabe bleibt in AdminBot-Policy und Code.

Wichtig fuer `v1.x`:

- Autorisierung folgt echten lokalen Peer-Credentials (`SO_PEERCRED`, Unix-User, Unix-Gruppen)
- `requested_by.type` und `requested_by.id` dienen nur Audit, Korrelation und UX
- wenn Human- und Agent-Rollen unterschiedlich berechtigt sein sollen, muessen sie ueber getrennte Unix-User oder Gruppen getrennt werden

## Daemon starten

Der Daemon erwartet standardmäßig:

- Policy: `/etc/adminbot/policy.toml`
- Socket: `/run/adminbot/adminbot.sock`
- Socket-Gruppe: `adminbotctl`

Vor dem Start:

```bash
sudo install -d -o adminbot -g adminbot -m 0750 /run/adminbot
```

`adminbotd` startet fail closed, wenn `/run/adminbot` nicht das erwartete Runtime-Verzeichnis ist oder wenn unter `/run/adminbot/adminbot.sock` ein unsicheres Alt-Artefakt liegt.

Dann:

```bash
cargo run
```

## Test via Unix Socket

Die mitgelieferten Skripte erzeugen das binäre `u32`-Length-Prefix und sprechen danach direkt mit dem Unix Domain Socket.

Success-Case:

```bash
./scripts/test_success_case.sh /run/adminbot/adminbot.sock
```

Policy-Deny-Case:

```bash
./scripts/test_policy_deny_case.sh /run/adminbot/adminbot.sock
```

Generisch mit JSON von `stdin`:

```bash
echo '{"version":1,"request_id":"2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62571","requested_by":{"type":"human","id":"local-cli"},"action":"system.status","params":{},"dry_run":false,"timeout_ms":3000}' | ./scripts/send_request.sh /run/adminbot/adminbot.sock -
```

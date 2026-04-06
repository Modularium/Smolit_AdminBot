# AdminBot v1 Read-only Action Sensitivity

## Ziel

Dieses Dokument klassifiziert die read-only Actions von AdminBot v1 nach
Informationsabfluss-Risiko und leitet daraus eine direkt nutzbare
Default-Policy-Guidance ab.

## Grundsatz

Nicht jede read-only Action ist gleich harmlos.

- `read_basic` ist fuer niedrigere Sensitivitaet gedacht
- `service_read` bleibt separat, weil Service-Metadaten betrieblich relevant sind
- `read_sensitive` ist bewusst opt-in und nicht fuer Default-Deployments gedacht

## Klassifikation

| Action | Capability | Sensitivitaet | Begründung |
| --- | --- | --- | --- |
| `system.status` | `read_basic` | niedrig | allgemeine Host- und Laufzeitübersicht ohne tiefe Prozess- oder Logdaten |
| `system.health` | `read_basic` | niedrig | verdichtete Check-Sicht, keine rohe Detailausleitung |
| `network.interface_status` | `read_basic` | niedrig | Interface-Status, aber keine tiefen Prozess- oder Journaldaten |
| `resource.snapshot` | `read_basic` | mittel | Host-Auslastung und Kapazitätsbild können Betriebsprofile offenlegen |
| `disk.usage` | `read_basic` | mittel | Dateisystem- und Kapazitätsdaten zeigen Struktur und Engpässe des Hosts |
| `service.status` | `service_read` | mittel | verrät konkrete Unit-Namen und Lebenszykluszustände produktiver Dienste |
| `process.snapshot` | `read_sensitive` | hoch | gibt laufende Prozesse, Kommandos und PIDs preis |
| `journal.query` | `read_sensitive` | hoch | liefert potenziell sensible Betriebs-, Fehler- und Nutzdaten aus journald |

## Default-Policy-Guidance

Empfohlener Default fuer neue Deployments:

1. `read_basic` nur fuer lokale Operatoren mit echtem Diagnosebedarf
2. `service_read` nur zusaetzlich vergeben, wenn konkrete Service-Zustaende benoetigt werden
3. `read_sensitive` standardmaessig **nicht** vergeben
4. `journal.query` und `process.snapshot` nur nach expliziter Review aktivieren

## Empfohlene Freigabeprofile

### Minimales Read-only Profil

- `system.status`
- `system.health`
- `network.interface_status`

### Operatives Diagnoseprofil

- Minimales Read-only Profil
- `resource.snapshot`
- `disk.usage`
- `service.status`

### Sensitives Incident-Profil

- Operatives Diagnoseprofil
- `process.snapshot`
- `journal.query`

Dieses Profil ist nur fuer klar benannte lokale Admin-Identitaeten gedacht und
nicht fuer generische Agent- oder Alltags-CLI-Kontexte.

## Nicht empfohlen

Diese Muster sollten vermieden werden:

- `read_sensitive` pauschal an denselben Unix-User wie Alltags-Read-only geben
- `journal.query` ohne explizite Unit-Whitelist und Betreiberbedarf freigeben
- `process.snapshot` an Agent-Kontexte vergeben, die keine Incident-Analyse machen

## Bezug zum Beispiel-Policy-Artefakt

Die versionierte `config/policy.example.toml` folgt dieser Guidance:

- kein `read_sensitive` im Default
- kein `journal.query` im Default
- kein `process.snapshot` im Default
- keine mutierenden Actions im Default

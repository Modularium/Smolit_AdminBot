# Agent-NN Integration für AdminBot v2

## Rolle von Agent-NN

`Agent-NN` übernimmt künftig:

- Zielinterpretation
- Planung
- Zerlegung in Handlungsschritte
- Orchestrierung
- Auswahl dedizierter AdminBot-Tools
- Kontext- und Session-Führung

`Agent-NN` übernimmt ausdrücklich nicht:

- privilegierte lokale Ausführung
- freie Shell-Kontrolle über den Host
- Umgehung des AdminBot-Policy-Layers

## Rolle des künftigen AdminBot-Agent

Der spätere `AdminBot-Agent` in `Agent-NN` ist keine allgemeine Root- oder Ops-Instanz, sondern eine kontrollierte Integrationskomponente.

Seine Aufgabe:

- AdminBot-relevante Nutzerziele interpretieren
- daraus dedizierte Tool-Aufrufe bilden
- Ergebnisse zurück in `Agent-NN` überführen
- bei mutierenden Aktionen standardmäßig Dry-Run oder Preflight voranstellen

## Platzierung in Agent-NN

## Verbindliche Empfehlung

Ein dedizierter Worker-Service oder dedizierter MCP-naher Service ist dem generischen Plugin-Modell klar vorzuziehen.

Begründung:

- besser an Dispatcher, Registry, Governance und Audit anschließbar
- klarer Lebenszyklus
- bessere Begrenzung von Fähigkeiten
- saubere Trennung zu offenen Tool-Experimenten

## Warum nicht generisches Plugin?

Das generische Plugin-Muster ist für AdminBot zu offen:

- potenziell beliebige lokale Dateizugriffe
- potenziell beliebige HTTP-Aufrufe
- zu schwache Capability-Grenzen
- Gefahr der Umgehung zentraler Sicherheits- und Governance-Pfade

Für sicherheitskritische Systemadministration ist das nicht die richtige Integrationsform.

## Integrationsprinzip

Der `AdminBot-Agent` nutzt nur feste, vorab definierte Tools. Diese Tools sind keine freie Action-Passthrough-Schicht.

Verboten:

- generisches `adminbot_execute_anything`
- freie Übergabe beliebiger Action-Namen
- freie Übergabe beliebiger Parameterobjekte ohne Tool-spezifische Validierung

Erlaubt:

- feste Tool-Namen mit festem Mapping auf erlaubte AdminBot-Actions

## Tool Interface auf hoher Ebene

Jedes Tool soll:

- eine kleine, feste Eingabestruktur haben
- auf genau eine Action oder eine feste kleine Action-Kombination mappen
- explizite Grenzen für Whitelists, Limits und Mutationen einhalten
- AdminBot-Responses möglichst 1:1 weiterreichen

## Dedizierte Tools, Variante A

## `adminbot_get_system_status`

- Zweck:
  - Systemgrundzustand abrufen
- Mapping:
  - `system.status`
- Grenzen:
  - read-only
  - nur `detail = basic|extended`
- Input:
  - `detail`
- Output:
  - strukturierter Statusblock

## `adminbot_get_system_health`

- Zweck:
  - Gesundheitszustand strukturiert abfragen
- Mapping:
  - `system.health`
- Grenzen:
  - read-only
  - nur definierte Check-Mengen
- Input:
  - `include_checks`
- Output:
  - Health-Status und Warnungen

## `adminbot_get_service_status`

- Zweck:
  - Status einer freigegebenen Unit abrufen
- Mapping:
  - `service.status`
- Grenzen:
  - nur `.service`
  - nur Whitelist-Units laut AdminBot-Policy
- Input:
  - `unit`
- Output:
  - Service-Zustand

## `adminbot_restart_service`

- Zweck:
  - kontrollierter Neustart einer freigegebenen Unit
- Mapping:
  - `service.restart`
- Grenzen:
  - nur Whitelist-Units
  - keine freien Flags
  - in `v1` nur `mode = safe`
  - Tool soll standardmäßig Dry-Run vor echter Mutation verwenden
- Input:
  - `unit`
  - `reason`
  - `dry_run`
- Output:
  - Ergebnis, Warnungen, Audit-Referenz

## `adminbot_collect_diagnostics`

- Zweck:
  - kleine, strukturierte Diagnose über mehrere read-only Aktionen
- Mapping:
  - `system.status`
  - `system.health`
  - `resource.snapshot`
  - optional `journal.query`
- Grenzen:
  - rein lesend
  - feste Obergrenzen für Journal- und Prozessdaten
- Input:
  - `profile = basic`
- Output:
  - gebündelte Diagnose

## `adminbot_check_disk_usage`

- Zweck:
  - Dateisystemnutzung prüfen
- Mapping:
  - `disk.usage`
- Grenzen:
  - nur freigegebene Mountpoints
- Input:
  - `mounts`
- Output:
  - Nutzung je Mountpoint

## `adminbot_get_recent_journal`

- Zweck:
  - letzte relevante Journald-Einträge abfragen
- Mapping:
  - `journal.query`
- Grenzen:
  - enge Limits
  - nur definierte Units oder Prioritäten
- Input:
  - `unit`
  - `priority_min`
  - `since_seconds`
  - `limit`
- Output:
  - strukturierte Journal-Liste

## Tool-Designregeln

Für alle dedizierten Tools gilt:

- kein generischer `action`-Passthrough
- kein generischer `params`-Passthrough ohne Tool-spezifische Validierung
- keine Übergabe freier Shell-Befehle
- mutierende Tools verlangen `reason`
- `correlation_id` aus dem Agent-Lauf wird an AdminBot weitergereicht
- mutierende Tools verwenden zuerst Dry-Run oder Preflight, wenn sinnvoll

## Beispiel Mapping

Natürlichsprachiges Ziel:

- "Prüfe, ob nginx läuft und starte ihn neu, falls er hängt"

Erlaubtes Mapping in `Agent-NN`:

1. `adminbot_get_service_status(unit="nginx.service")`
2. Bewertung in `Agent-NN`
3. `adminbot_restart_service(unit="nginx.service", reason="...")` zunächst als Dry-Run
4. erst danach echte Mutation, falls Policy und Zustand passen

Nicht erlaubt:

- direkter Shell-Befehl
- direkte Root-Ausführung
- freie Action `"service.restart"` aus Prompttext ohne Tool-Layer

## Rollen, Fähigkeiten und Governance

Ein künftiger `AdminBot-Agent` in `Agent-NN` sollte nur begrenzte Fähigkeiten erhalten.

Sinnvolle Eigenschaften:

- Rolle:
  - eher `analyst` oder dedizierte Operations-Rolle mit begrenztem Scope
- Skills:
  - `system_diagnostics`
  - `service_operations_read`
  - optional später `service_operations_mutate`

## Governance-Vorgaben

- read-only und mutierende Tools werden getrennt freigegeben
- mutierende Tools nur mit expliziter Fähigkeit
- Rate-Limits auf Tool-Ebene
- Schutz gegen Tool-Loops:
  - gleiche mutierende Aktion nicht mehrfach in kurzer Folge
  - Restart-Schleifen blockieren
- Dry-Run-first als Standardmuster

## Wichtige Sicherheitsgrenze

Auch wenn `Agent-NN` später einen `AdminBot-Agent` besitzt, gilt:

- `Agent-NN` darf nie direkt Root ausführen
- `Agent-NN` darf nie direkt D-Bus/polkit-Privilegien verwalten
- `Agent-NN` darf nur AdminBot anfragen
- AdminBot entscheidet lokal

## V1-Festlegung für Capabilities

Für `v1` wird empfohlen:

- `Agent-NN` erhält standardmäßig:
  - `read_basic`
  - `read_sensitive`
  - `service_read`
- `Agent-NN` erhält in `v1` standardmäßig nicht:
  - `service_control`

Begründung:

- der erste sichere Integrationsschritt ist Diagnose, nicht Mutation
- mutierende Agent-Requests können später mit zusätzlicher Governance freigeschaltet werden

## Architektur-Fazit

Die Integration mit `Agent-NN` bleibt bewusst eng geführt. Nicht ein generischer Plugin-Kanal, sondern ein dedizierter AdminBot-Agent mit festen Tools sorgt für kontrollierte Orchestrierung. `Agent-NN` plant, aber `AdminBot` bleibt die einzige lokale Instanz, die mutierende Entscheidungen technisch vollzieht.

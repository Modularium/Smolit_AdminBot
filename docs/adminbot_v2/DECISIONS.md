# Architekturentscheidungen für AdminBot v2

## ADR-001: AdminBot wird in Rust neu gebaut

- Status: beschlossen
- Kontext:
  - der bisherige Python-Ansatz ist inkonsistent, schwergewichtig und sicherheitlich ungeeignet
- Entscheidung:
  - der neue AdminBot-Core wird vollständig als nativer Rust-Dienst entworfen
- Folge:
  - kein Python-Core mehr
  - Fokus auf geringer Laufzeitlast, Vorhersagbarkeit und Härtung

## ADR-002: Kein ML/LLM im Core

- Status: beschlossen
- Kontext:
  - ML/LLM erhöhen Footprint, Angriffsfläche und Nichtdeterminismus
- Entscheidung:
  - der Core enthält keinerlei ML- oder LLM-Funktionalität
- Folge:
  - Denklogik liegt außerhalb des Dienstes

## ADR-003: AdminBot bleibt lokaler Executor, Agent-NN bleibt Planer

- Status: beschlossen
- Kontext:
  - Planung und privilegierte Ausführung müssen sauber getrennt werden
- Entscheidung:
  - `Agent-NN` übernimmt Planung und Orchestrierung
  - `AdminBot` übernimmt lokale Ausführung und Policy-Entscheidung
- Folge:
  - klare Sicherheitsgrenze

## ADR-004: Unix Domain Socket ist die primäre lokale Schnittstelle

- Status: beschlossen
- Kontext:
  - AdminBot soll lokal, schlank und hart begrenzt sein
- Entscheidung:
  - primäre IPC über Unix Domain Socket
- Folge:
  - kein offener Netzwerkdienst als Standard
  - Peer-Credential-Prüfungen werden möglich

## ADR-005: IPC nutzt JSON über length-prefixed Framing

- Status: beschlossen
- Kontext:
  - das IPC-Protokoll muss robust und direkt implementierbar sein
- Entscheidung:
  - JSON in UTF-8
  - 4-Byte-Length-Prefix vor jedem Payload
  - Protokollversion als Integer im Feld `version`
- Folge:
  - keine newline-delimited Nachrichten in `v1`
  - unbekannte Versionen führen zu `unsupported_version`

## ADR-006: Keine freie Shell-Ausführung

- Status: beschlossen
- Kontext:
  - freie Shell-Ausführung ist für einen hochsicheren Admin-Dienst nicht vertretbar
- Entscheidung:
  - keine `run command`-, `exec`- oder Shell-API
- Folge:
  - Action Registry wird zur zentralen Positivliste

## ADR-007: Statische Action Registry statt offenem Plugin-Core

- Status: beschlossen
- Kontext:
  - offene Plugins im Core vergrößern die Angriffsfläche
- Entscheidung:
  - der Core kennt nur statisch registrierte Aktionen
- Folge:
  - Erweiterungen erfolgen kontrolliert über Releases

## ADR-008: V1-Scope bleibt klein und read-only-lastig

- Status: beschlossen
- Kontext:
  - der frühere Ansatz war überladen
- Entscheidung:
  - `v1` fokussiert auf Status-, Health-, Journal-, Ressourcen- und ausgewählte Service-Aktionen
- Folge:
  - schnellere Härtung
  - bessere RasPi-Eignung

## ADR-009: `service.start` und `service.stop` sind nicht Teil von v1

- Status: beschlossen
- Kontext:
  - mutierende Aktionen sollen im ersten Schritt minimal bleiben
- Entscheidung:
  - `v1` enthält mutierend nur `service.restart`
- Folge:
  - geringerer Scope
  - kleinere Missbrauchsfläche

## ADR-010: Service-Control nutzt primär systemd D-Bus plus polkit

- Status: beschlossen
- Kontext:
  - `adminbotd` soll non-root bleiben
- Entscheidung:
  - `service.restart` wird in `v1` primär über systemd D-Bus plus polkit umgesetzt
  - verbindlicher Pfad ist `org.freedesktop.systemd1.Manager.RestartUnit`
  - einzig erlaubter systemd-Mode in `v1` ist `"replace"`
  - einzig erlaubter AdminBot-Mode in `v1` ist `safe`
  - festes Mapping `safe -> RestartUnit(unit, "replace")`
- Folge:
  - kein Root-Daemon notwendig
  - keine Capability-basierte Scheinlösung
  - kein `systemctl`, kein Shell-Fallback und kein alternativer Restart-Pfad in `v1`

## ADR-011: Dedizierter Root-Helper ist nur Reserveoption

- Status: beschlossen
- Kontext:
  - manche Systeme könnten D-Bus/polkit unzureichend bereitstellen
- Entscheidung:
  - Root-Helper wird dokumentiert, aber nicht als `v1`-Standardpfad umgesetzt
- Folge:
  - privilegierter Eigen-Code bleibt vorerst minimiert

## ADR-012: Linux Capabilities sind nicht der Primärweg für Service-Control

- Status: beschlossen
- Kontext:
  - Service-Steuerung über systemd lässt sich nicht sinnvoll über wenige Capabilities modellieren
- Entscheidung:
  - Capabilities werden nicht als Hauptstrategie für `service.restart` verwendet
- Folge:
  - weniger unsaubere Privilegmischung

## ADR-013: Mutierende Aktionen werden enger kontrolliert als read-only Aktionen

- Status: beschlossen
- Kontext:
  - nicht jede Aktion hat dasselbe Risikoprofil
- Entscheidung:
  - getrennte Capability- und Policy-Behandlung für read-only und mutierende Aktionen
- Folge:
  - `service.restart` nur eng begrenzt

## ADR-014: Policy-Modell v1 ist statisches TOML

- Status: beschlossen
- Kontext:
  - das Policy-System muss einfach und wartbar bleiben
- Entscheidung:
  - statisch ladbares TOML mit Clients, Capabilities, Action-Whitelist und Constraints
- Folge:
  - kein Overengineering durch DSL oder komplexe Policy-Engine

## ADR-015: Agent-NN nutzt dedizierte Tools statt generischer Plugins

- Status: beschlossen
- Kontext:
  - das generische Plugin-Modell ist für Admin-Aktionen zu offen
- Entscheidung:
  - späterer `AdminBot-Agent` nutzt dedizierte Tools mit festem Action-Mapping
- Folge:
  - keine freie Tool- oder Shell-Kontrolle über AdminBot

## ADR-016: Agent-NN erhält in v1 standardmäßig keine `service_control`-Capability

- Status: beschlossen
- Kontext:
  - die erste sichere Integrationsstufe soll read-only sein
- Entscheidung:
  - `Agent-NN` erhält in `v1` standardmäßig nur Diagnose- und Service-Read-Zugriffe
- Folge:
  - mutierende Agentenpfade werden bewusst auf später verschoben

## ADR-017: Auditierbarkeit ist Pflichtbestandteil, kein Add-on

- Status: beschlossen
- Kontext:
  - privilegierte oder sicherheitsrelevante Aktionen müssen nachvollziehbar bleiben
- Entscheidung:
  - jeder Request erhält Korrelation, Audit-Referenz und strukturierte Protokollierung
- Folge:
  - Unterschiede zwischen menschlichen und maschinellen Requests bleiben sichtbar

## ADR-018: Globales IPC-Fehlermodell ist verbindlich

- Status: beschlossen
- Kontext:
  - CLI, `Agent-NN` und spätere UIs brauchen stabile maschinenlesbare Fehler
- Entscheidung:
  - Fehlerantworten folgen in `v1` einem festen Objekt mit `request_id`, `status = error` und `error.{code,message,details,retryable}`
  - die Fehlercodeliste ist für `v1` stabil definiert
- Folge:
  - keine freie Textfehler-Semantik als Primärvertrag
  - Retry-Verhalten kann sauber zwischen finalen und temporären Fehlern unterscheiden

## ADR-019: systemd ist der primäre Betriebsrahmen

- Status: beschlossen
- Kontext:
  - AdminBot ist ein nativer Linux-Dienst
- Entscheidung:
  - `systemd` ist primärer Prozess- und Härtungsrahmen
- Folge:
  - keine konkurrierenden Supervisor-, Shell- oder Docker-Primärpfade

## ADR-020: `RestrictAddressFamilies=AF_UNIX` bleibt Zielwert

- Status: beschlossen
- Kontext:
  - der Daemon soll lokal, klein und hart eingegrenzt bleiben
- Entscheidung:
  - `RestrictAddressFamilies=AF_UNIX` bleibt für `v1` der Zielwert
  - systemd D-Bus und polkit werden explizit gegen diese Härtung verifiziert
- Folge:
  - Erweiterungen sind nur minimal und begründet zulässig
  - der Punkt ist Implementierungs- und Verifikationsarbeit, kein offener Architekturstreit mehr

## ADR-021: Low-End-Hardware-Tauglichkeit ist harte Anforderung

- Status: beschlossen
- Kontext:
  - Zielhardware umfasst Raspberry Pi und ältere Systeme
- Entscheidung:
  - Architektur und `v1`-Scope priorisieren niedrigen Footprint
- Folge:
  - keine schweren Dauerprozesse im Core

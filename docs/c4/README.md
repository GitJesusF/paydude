# C4 diagrams (C4-PlantUML)

Canonical [C4 model](https://c4model.com) sources for PayDude, written in
[C4-PlantUML](https://github.com/plantuml-stdlib/C4-PlantUML) notation. These are the
higher-fidelity originals; the [`../architecture.md`](../architecture.md) (arc42) doc embeds Mermaid
renditions of the same views so they display inline on GitHub.

| File | C4 level | View |
|------|----------|------|
| [`context.puml`](context.puml) | 1 — System Context | PayDude + its users, HaveIBeenPwned and the TOTP authenticator |
| [`container.puml`](container.puml) | 2 — Container | API, PostgreSQL, Prometheus/Loki/Promtail/Grafana |
| [`component-api.puml`](component-api.puml) | 3 — Component | Internals of the Spring Boot API container |
| [`transfer-dynamic.puml`](transfer-dynamic.puml) | Dynamic | Idempotent transfer flow |

## Rendering

The diagrams `!include <C4/...>`, which resolves against the C4-PlantUML library bundled in
PlantUML's standard library (PlantUML ≥ 1.2022). Pick whichever is convenient:

```bash
# 1. PlantUML CLI / jar (needs Graphviz for layout)
plantuml -tsvg docs/c4/*.puml          # emits *.svg next to each source

# 2. Docker (no local install)
docker run --rm -v "$PWD:/work" -w /work plantuml/plantuml -tsvg docs/c4/*.puml

# 3. IDE: the PlantUML plugin for IntelliJ / the "PlantUML" VS Code extension
#    render on save and preview live.
```

If your PlantUML predates the bundled C4 stdlib, swap the first `!include` in each file for the
remote form, e.g.:

```plantuml
!includeurl https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Container.puml
```

## Structurizr (optional)

These files are also a natural fit for [Structurizr](https://structurizr.com) / the Structurizr DSL
if the project ever wants a single model that generates all levels — the C4-PlantUML notation here
maps one-to-one onto Structurizr's element types (`Person`, `System`, `Container`, `Component`).

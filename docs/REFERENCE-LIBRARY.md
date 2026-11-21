# Reference library inventory (2026-11-22)

| TrillionAI repository | Upstream project | Status observed |
| --- | --- | --- |
| Reference-Apache-Camel | https://github.com/apache/camel | README only; source import pending |
| Reference-Node-RED | https://github.com/node-red/node-red | README only; source import pending |
| Temporal-Source-Code-Reference | https://github.com/temporalio/temporal | Temporal server source already imported; NOT the TypeScript SDK |
| Reference-Meltano-Singer-SDK | https://github.com/meltano/sdk | README only; source import pending |
| Reference-Debezium | https://github.com/debezium/debezium | README only; source import pending |
| Reference-Ballerina-Library | https://github.com/ballerina-platform/ballerina-library | README only; source import pending |
| Reference-Eclipse-Kura | https://github.com/eclipse-kura/kura | README only; source import pending |
| Reference-Eclipse-Milo | https://github.com/eclipse-milo/milo | README only; source import pending |

Do not label an unimported repository a source-code reference. Use pinned upstream commits, retain upstream licence, notices and provenance, and review copyleft/commercial obligations before copying code into this product.

Implementation order: connector SDK and registry; Identity-authenticated gateway; durable tenancy and token storage; protocol adapters; workflow and observability; AI-assisted adapter engineering; Manager contracts and payments. No provider is considered connected merely because it appears in a catalog.

Security: this prototype SDK **does not authenticate requests** or verify approval records. It must only be called behind a server that derives context from verified identities and checked policies. Do not expose it directly as an unauthenticated API.

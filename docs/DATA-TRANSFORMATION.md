# Provider-neutral data transformation

The transformation engine translates JSON-like provider records to canonical, policy-approved fields via declarative mappings.

It supports safe nested own-property reads, required/optional fields, finite numeric parsing, boolean conversion, string conversion, and raw values. Invalid mappings, duplicate targets, unsafe property names and incompatible values fail closed.

This is a small independently executable baseline for data normalization across CRM, accounting and external connector records. It is **not** a full ETL system: it does not perform bulk extraction, schema inference, binary conversion, PII redaction, streaming, deduplication, schema evolution or authorization. Those belong to separately verified subsystems.

The engine intentionally does not execute user expressions or transformation scripts. Custom provider transformations should execute in isolated, permission-limited adapters.

Reference architectures worth consulting from the imported library: Apache Camel for integration patterns, Meltano Singer SDK for extraction contracts, Debezium for change-data capture, and Node-RED for visual workflow composition. Reuse source only after dependency and licence review.

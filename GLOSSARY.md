# AI Enablement Gateway

Governance control plane, model router, and guarded tool runtime that mediates all LLM and MCP traffic for internal engineering teams.

## Identity & Governance

**Credential**:
A caller-supplied proof of identity—either a signed JWT or a scoped API key—used to authenticate requests at the **Control Plane**.
_Avoid_: Token (ambiguous with **LLM Token**), secret

**Actor**:
The authenticated identity resolved from a **Credential**, belonging to exactly one **Team** and holding one **Role**.
_Avoid_: User, client, caller

**Team**:
The tenant boundary that owns **Model Alias** allowlists, rate limits, and **Budget Quotas**.
_Avoid_: Org, project, tenant, group

**Role**:
An **Actor**'s privilege tier (such as `developer`, `ops`, or `admin`) that governs **MCP Tool** access alongside **Team**.
_Avoid_: Scope, permission group

**Policy Bundle**:
The immutable, versioned collection of governance rules (RBAC, routing/pricing, and safety) loaded atomically by the **Control Plane** and stamped by version on every **Audit Event**.
_Avoid_: Config set, rule file

**Budget Quota**:
The spending or **LLM Token** allowance enforced for a **Team** over a defined window via upfront reservation and post-completion reconciliation.
_Avoid_: Credit, cap, limit

## Routing & Execution

**Control Plane**:
The single governed front door that authenticates **Credentials**, enforces **Policy Bundles** and **Budget Quotas**, executes pre-call guardrails, and emits **Audit Events** for both LLM and MCP traffic.
_Avoid_: Proxy, router

**Model Router**:
The stateless data-plane component that translates a **Model Alias** into upstream **Provider** calls, handling retries, timeouts, and primary-to-fallback failover.
_Avoid_: Gateway, backend

**Model Alias**:
A logical model name requested by an **Actor** (such as `chat-default` or `chat-fast`) that the **Model Router** maps to one or more concrete upstream **Providers**.
_Avoid_: Model ID, deployment name

**Provider**:
An external or self-hosted model endpoint (or deterministic local mock) reachable only by the **Model Router**.
_Avoid_: Upstream, vendor, model server

**LLM Token**:
A unit of prompt or completion text billed by a **Provider** and counted against a **Team**'s **Budget Quota**.
_Avoid_: Auth token

## Guarded Tools & Observability

**MCP Tool**:
A deterministic, read-only operational capability exposed by the **MCP Runtime** behind **Role**- and **Team**-scoped allowlists.
_Avoid_: Function, plugin, action

**MCP Runtime**:
The isolated service hosting **MCP Tools**, trusting only signed identity assertions from the **Control Plane** and enforcing per-call timeouts and **Run** loop caps.
_Avoid_: Agent server, tool proxy

**Run**:
A bounded agent workflow invocation identified by a single run ID, across which the **MCP Runtime** enforces a maximum tool-call loop cap.
_Avoid_: Session, thread, execution

**Audit Event**:
A structured, privacy-safe log record emitted for every governed LLM or **MCP Tool** invocation, capturing identity, **Policy Bundle** version, routing/failover outcome, cost, and hashes—never raw prompt content or PII.
_Avoid_: Access log, trace log

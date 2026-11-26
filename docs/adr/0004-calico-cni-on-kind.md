---
status: accepted
---

# Calico CNI on Local Kind for Real NetworkPolicy Enforcement

Configure local and CI `kind` clusters with `disableDefaultCNI: true` and install Calico so Kubernetes `NetworkPolicy` manifests are genuinely enforced at runtime. Default `kind` uses `kindnet`, which silently accepts `NetworkPolicy` objects without enforcing them.

## Considered Options

- **Default `kindnet` CNI:** Fastest cluster startup, but zero-trust isolation claims would be untested theater.
- **Cilium CNI:** Stronger eBPF observability and L7 policy capabilities, but heavier startup footprint and kernel/runner sensitivity in GitHub Actions `kind` jobs.

## Consequences

- `make up` and CI integration jobs take ~30–60s longer during cluster bootstrap while Calico initializes.
- CI can run automated negative connectivity tests proving blocked paths (such as `gateway-api` → `mock-llm` or `mcp-runtime` → internet) actually time out or fail.

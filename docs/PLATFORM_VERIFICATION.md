# Platform Verification Notes — 20 August 2026

This file records current external platform facts used by the architecture. It is intentionally separate from Delegation Fabric's own design contracts because Google Cloud launch stages, locations and APIs can change.

Re-check these links immediately before submission.

---

## 1. Agent Platform regional support

Current Google Cloud documentation lists `asia-south1` (Mumbai) as supporting:

- Agent Runtime
- Sessions
- Agent Platform Memory Bank
- Agent Gateway

Source:

- https://docs.cloud.google.com/gemini-enterprise-agent-platform/resources/agent-locations

Architecture consequence:

```text
The runtime/session/memory/gateway plane can remain regional in asia-south1 for the selected deployment.
```

---

## 2. Agent Registry

Agent Registry is the platform catalog for agents, MCP servers, endpoints, skills and related metadata.

Agent Runtime deployments support automatic registration.

Sources:

- https://docs.cloud.google.com/agent-registry/overview
- https://docs.cloud.google.com/agent-registry/register-agents

Architecture consequence:

```text
Delegation Fabric must not build a competing agent registry.
```

Keep only authorization-specific metadata/cache needed by the application.

---

## 3. Semantic Governance

Semantic Governance:

- evaluates proposed tool calls against user intent and natural-language constraints;
- is an additional layer, not a replacement for IAM;
- uses an LLM and can produce incorrect verdicts;
- can target tool parameters in natural-language constraints;
- should be dry-run tested before enforcement.

Sources:

- https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/semantic-governance-overview
- https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/configure-semantic-governance

Architecture consequence:

Delegation Fabric's novelty cannot be stated merely as "purpose-aware or parameter-aware tool policy."

The stronger distinction is:

```text
semantic intent evaluation
vs
deterministic human-anchored transaction credential
```

Delegation Fabric adds:

- cryptographically signed Execution Grant;
- exact task/delegation binding;
- transactional single-use consumption;
- approval/SOD binding;
- response-field projection;
- causal application audit chain.

---

## 4. Model Armor

Model Armor provides prompt injection/jailbreak detection and sensitive-data protections.

Current release notes/documentation indicate Mumbai (`asia-south1`) data-residency support and the current filter versions for that region.

Sources:

- https://docs.cloud.google.com/model-armor
- https://docs.cloud.google.com/model-armor/release-notes
- https://docs.cloud.google.com/model-armor/sanitize-prompts-responses

Architecture consequence:

Use a regional Model Armor endpoint/template and store the template/filter version in evidence when useful.

---

## 5. Pub/Sub delivery semantics

Pub/Sub defaults to at-least-once delivery.

Exactly-once delivery is supported for pull/StreamingPull subscriptions, not push subscriptions.

Sources:

- https://docs.cloud.google.com/pubsub/docs/subscription-overview
- https://docs.cloud.google.com/pubsub/docs/exactly-once-delivery

Architecture consequence:

For the chosen Cloud Run push worker:

```text
correctness depends on application-level event idempotency.
```

Use stable `event_id`, Firestore receipts and state-version transactions.

---

## 6. Cloud Run service-to-service authentication

Google recommends per-service user-managed service accounts with least privilege. Authenticated service-to-service requests use Google-signed OIDC ID tokens with the receiving service as the audience.

Sources:

- https://docs.cloud.google.com/run/docs/authenticating/service-to-service
- https://docs.cloud.google.com/run/docs/configuring/services/service-identity

Architecture consequence:

Do not expose Control Plane/Execution Gateway publicly simply for convenience. Use service identities and narrow `roles/run.invoker` bindings.

---

## 7. Cloud KMS signing

Cloud KMS supports asymmetric signing keys.

Google currently recommends elliptic-curve signing and identifies `EC_SIGN_P256_SHA256` as the recommended EC signing algorithm.

Sources:

- https://docs.cloud.google.com/kms/docs/algorithms
- https://docs.cloud.google.com/kms/docs/create-key
- https://docs.cloud.google.com/kms/docs/create-validate-signatures

Architecture consequence:

Use KMS for the Execution Grant signing key. Private key material never enters the application container.

---

## 8. Gemini model choice

`gemini-3.5-flash` is available in `asia-south1` according to the current model documentation.

Source:

- https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/gemini/3-5-flash

Newer models can exist without the same regional serving footprint.

Architecture consequence:

Do not upgrade the demo model simply because it is newer. Re-check regionality first.

---

## 9. Verification checklist before final submission

- [ ] region support unchanged
- [ ] model serving location unchanged
- [ ] Agent Registry behavior unchanged
- [ ] Agent Gateway configuration path works
- [ ] Semantic Governance launch stage disclosed accurately
- [ ] Model Armor template/filter version pinned/documented
- [ ] KMS key/version enabled
- [ ] Pub/Sub docs still match delivery claim
- [ ] no README claim conflicts with current product docs

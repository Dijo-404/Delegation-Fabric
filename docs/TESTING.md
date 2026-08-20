# Testing Strategy

Security claims must exist as executable tests, not just README statements.

---

## 1. Test pyramid

```text
unit              many
integration       medium
security          medium
end-to-end        few, high-value
demo smoke        very few
```

---

## 2. Unit tests

### Constraints

For every operator:

- allowed;
- boundary;
- denied;
- wrong type;
- missing path;
- malformed value.

### Projection

- top-level field;
- nested field;
- arrays;
- missing allow-list;
- unknown fields;
- forbidden field dropped.

### Audit chain

- valid;
- middle event modified;
- order changed;
- missing event;
- incorrect previous hash.

### State machine

Every allowed transition and representative denied transition.

---

## 3. Grant crypto tests

- correct signature;
- tampered payload;
- tampered signature;
- unknown key id;
- wrong issuer;
- wrong audience;
- not-before;
- expiry;
- wrong algorithm rejected.

Use a local test key for unit tests; KMS integration test separately.

---

## 4. Grant lifecycle integration tests

| Test | Expected |
| --- | --- |
| valid grant | executes |
| replay | `GRANT_REPLAYED` |
| expired | `GRANT_EXPIRED` |
| wrong tool | `GRANT_TOOL_MISMATCH` |
| wrong task | `GRANT_TASK_MISMATCH` |
| revoked delegation | deny |
| invalid args | deny |
| missing approval | deny |
| approval mismatch | deny |
| SOD violation | deny |

---

## 5. Event tests

- normal approval event;
- same `event_id` twice;
- concurrent duplicate deliveries;
- invalid schema;
- invalid state transition;
- worker crash after reservation;
- worker crash after resume but before final checkpoint;
- DLQ after retry threshold.

Verify no duplicate side effect.

---

## 6. Database tests

- reconciliation role reads invoice;
- reconciliation role cannot read bank account;
- treasury role cannot access unrelated tables;
- `payments.grant_id` uniqueness prevents duplicate mutation;
- amount constraints and SQL checks.

---

## 7. Security tests

### Prompt injection

Poisoned fixture attempts forbidden read/egress.

Pass condition:

```text
no unauthorized side effect
+ deterministic denial reason
+ quarantine/audit evidence
```

### Cross-agent escalation

Invoice agent attempts treasury capability.

Pass:

```text
no grant minted
```

### Approval bypass

Try:

- same human where SOD forbids;
- wrong batch;
- expired approval;
- modified amount.

All deny.

---

## 8. Model Armor/Semantic Governance tests

Do not make tests flaky by asserting exact natural-language rationale.

Assert stable categories/verdict classes where the API supports them.

Keep recorded fixtures/mocks for CI and one live smoke test for deployment verification.

---

## 9. End-to-end happy path

```text
create delegation
-> start reconciliation
-> process invoice
-> create exception
-> wait
-> approval
-> event
-> resume
-> treasury grant
-> payment
-> complete
-> verify audit chain
```

---

## 10. Long-running simulation

The demo fixture can seed historical timestamps, but the code path must be identical to real resumption.

Test:

- checkpoint from "18 days ago";
- worker has no in-memory state;
- approval event arrives;
- task resumes from persisted IDs;
- fresh grant issued.

---

## 11. Coverage

Targets:

```text
delegation_fabric_core >= 85%
overall Python >= 70%
```

Coverage is not a substitute for adversarial cases.

---

## 12. CI matrix

```text
python lint
python typecheck
python unit
python integration-with-emulators/mocks
frontend lint
frontend typecheck
frontend test
terraform fmt
terraform validate
security fixture tests
```

Optional nightly/manual:

```text
live GCP smoke
live KMS sign/verify
live Model Armor
live Agent Runtime
```

---

## 13. Test naming

Prefer:

```text
test_payment_grant_denied_when_approval_subject_differs
test_duplicate_approval_event_does_not_resume_twice
test_reconciliation_role_cannot_select_bank_account_number
```

Avoid vague names such as:

```text
test_security
test_gateway
test_case_1
```

---

## 14. Demo preflight test

One command:

```bash
make demo-preflight
```

Checks:

- cloud auth;
- service URLs;
- agents deployed;
- KMS key enabled;
- DB reachable;
- fixture loaded;
- Pub/Sub subscription healthy;
- audit verification passes;
- attack commands ready.

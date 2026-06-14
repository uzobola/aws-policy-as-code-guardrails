# AWS Policy-as-Code Guardrails

Preventive guardrails that evaluate a Terraform plan **before apply** and fail the
build when a change would violate a security control. Written in OPA Rego, executed
with Conftest, unit-tested with `opa test`, and enforced as a CI gate.

This is the preventive, shift-left counterpart to my
[AWS NHI Governance Engine](https://github.com/uzobola/aws-nhi-governance-engine):
the engine detects risky non-human identities that already exist; these guardrails
stop a class of misconfigurations from being deployed in the first place. Both gate
CI on policy violations and map findings to NIST 800-53.

## Controls

| Policy | Denies | NIST 800-53 |
| --- | --- | --- |
| `s3_public.rego` | Public S3 ACLs; public-access-block settings left open | SC-7, AC-6(10) |
| `security_group.rego` | Security groups exposing port 22/3389 to `0.0.0.0/0` | SC-7 |
| `iam_wildcard.rego` | IAM policies granting `Action:*` on `Resource:*` | AC-6(10) |
| `encryption.rego` | Unencrypted RDS storage and EBS volumes | SC-28 |
| `tagging.rego` | Taggable resources missing a non-empty `Owner` tag | CM-8 |

## How it works

Conftest evaluates the JSON form of a Terraform plan against the `deny` rules in
`policies/`. Any `deny` message fails the run, which fails CI.

```bash
# 1. Produce a plan in JSON (in your Terraform project)
terraform plan -out=tfplan.bin
terraform show -json tfplan.bin > plan.json

# 2. Evaluate it
conftest test plan.json -p policies
```

The `examples/` directory contains a `compliant.plan.json` (passes) and a
`violating.plan.json` (trips every rule) so the behavior is demonstrable without
a live AWS account.

## Run it

```bash
# Unit tests for the policy logic (no cloud, no plan needed)
opa test policies/ -v

# Gate against the bundled examples
conftest test examples/compliant.plan.json -p policies   # passes
conftest test examples/violating.plan.json -p policies   # fails, by design
```

## Requirements

- [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) (for `opa test`)
- [Conftest](https://www.conftest.dev/install/) (for evaluating plans)

## CI

`.github/workflows/policy-check.yml` runs `opa test`, confirms the compliant plan
passes, and confirms the violating plan is blocked, so a green check means the
guardrails both load and actually enforce.

## Scope and limits

These are a focused starter set, not exhaustive coverage. They evaluate planned
resource attributes from `terraform show -json`; resources whose values are only
known after apply are not evaluated. The intent is a small, correct, tested set of
controls that runs in CI, extended over time rather than padded.

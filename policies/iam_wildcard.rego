# IAM policies must not grant Action:* on Resource:* (wildcard admin).
# NIST 800-53: AC-6(10) (automated enforcement of least privilege)
#
# Scope note: this evaluates customer-managed policies (aws_iam_policy),
# standalone role policies (aws_iam_role_policy), and inline policies declared
# on a role (aws_iam_role.inline_policy). It does NOT evaluate managed-policy
# attachments (aws_iam_role_policy_attachment): those reference a policy ARN whose
# document is not present in the Terraform plan, so they cannot be inspected at
# plan time. Account-level resolution of attached and AWS-managed policies is
# handled by the companion AWS NHI Governance Engine.
# assume_role_policy is intentionally excluded here: it is a trust policy
# (who may assume the role), not a permissions policy.
package main

import rego.v1

deny contains msg if {
	some rc in input.resource_changes
	rc.change.after != null
	rc.type in {"aws_iam_policy", "aws_iam_role_policy"}
	doc := json.unmarshal(rc.change.after.policy)
	some stmt in _statements(doc)
	_wildcard_admin(stmt)
	msg := sprintf("%s: grants Action '*' on Resource '*'; scope actions and resources (NIST AC-6(10))", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.change.after != null
	rc.type == "aws_iam_role"
	some inline in rc.change.after.inline_policy
	doc := json.unmarshal(inline.policy)
	some stmt in _statements(doc)
	_wildcard_admin(stmt)
	msg := sprintf("%s: inline policy '%s' grants Action '*' on Resource '*'; scope it (NIST AC-6(10))", [rc.address, inline.name])
}

_wildcard_admin(stmt) if {
	stmt.Effect == "Allow"
	_has_wildcard(stmt.Action)
	_has_wildcard(stmt.Resource)
}

_statements(doc) := doc.Statement if is_array(doc.Statement)

_statements(doc) := [doc.Statement] if not is_array(doc.Statement)

_has_wildcard(val) if val == "*"

_has_wildcard(val) if {
	is_array(val)
	"*" in val
}

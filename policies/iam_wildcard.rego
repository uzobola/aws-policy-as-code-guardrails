# IAM policies must not grant Action:* on Resource:* (wildcard admin).
# NIST 800-53: AC-6(10) (automated enforcement of least privilege)
package main

import rego.v1

deny contains msg if {
	some rc in input.resource_changes
	rc.type in {"aws_iam_policy", "aws_iam_role_policy"}
	doc := json.unmarshal(rc.change.after.policy)
	some stmt in _statements(doc)
	stmt.Effect == "Allow"
	_has_wildcard(stmt.Action)
	_has_wildcard(stmt.Resource)
	msg := sprintf("%s: grants Action '*' on Resource '*'; scope actions and resources (NIST AC-6(10))", [rc.address])
}

_statements(doc) := doc.Statement if is_array(doc.Statement)

_statements(doc) := [doc.Statement] if not is_array(doc.Statement)

_has_wildcard(val) if val == "*"

_has_wildcard(val) if {
	is_array(val)
	"*" in val
}

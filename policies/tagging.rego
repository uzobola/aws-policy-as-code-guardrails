# Taggable resources must carry a non-empty Owner tag for accountability.
# NIST 800-53: CM-8 (system component inventory / ownership)
package main

import rego.v1

taggable := {"aws_s3_bucket", "aws_instance", "aws_iam_role", "aws_db_instance", "aws_security_group"}

deny contains msg if {
	some rc in input.resource_changes
	rc.type in taggable
	is_object(rc.change.after)
	not _has_owner(rc.change.after)
	msg := sprintf("%s: missing a non-empty 'Owner' tag (NIST CM-8)", [rc.address])
}

_has_owner(after) if {
	after.tags.Owner
	after.tags.Owner != ""
}

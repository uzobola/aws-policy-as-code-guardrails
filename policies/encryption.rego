# Storage must be encrypted at rest.
# NIST 800-53: SC-28 (protection of information at rest)
package main

import rego.v1

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_db_instance"
	rc.change.after.storage_encrypted == false
	msg := sprintf("%s: RDS storage_encrypted is false; enable encryption at rest (NIST SC-28)", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_ebs_volume"
	rc.change.after.encrypted == false
	msg := sprintf("%s: EBS volume encrypted is false; enable encryption at rest (NIST SC-28)", [rc.address])
}

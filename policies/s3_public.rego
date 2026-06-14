# S3 must not be publicly exposed.
# NIST 800-53: SC-7 (boundary protection), AC-6(10) (least privilege enforcement)
package main

import rego.v1

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_acl"
	acl := rc.change.after.acl
	acl in {"public-read", "public-read-write", "authenticated-read"}
	msg := sprintf("%s: S3 ACL '%s' is public/broad; use 'private' (NIST SC-7, AC-6(10))", [rc.address, acl])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	some setting in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
	rc.change.after[setting] == false
	msg := sprintf("%s: public access block '%s' is false; all four must be true (NIST SC-7)", [rc.address, setting])
}

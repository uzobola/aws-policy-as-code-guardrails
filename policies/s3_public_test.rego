package main

import rego.v1

test_public_acl_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "aws_s3_bucket_acl.bad", "type": "aws_s3_bucket_acl",
		"change": {"actions": ["create"], "after": {"acl": "public-read"}},
	}]}
}

test_private_acl_allowed if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "aws_s3_bucket_acl.ok", "type": "aws_s3_bucket_acl",
		"change": {"actions": ["create"], "after": {"acl": "private"}},
	}]}
}

test_open_public_access_block_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "aws_s3_bucket_public_access_block.bad", "type": "aws_s3_bucket_public_access_block",
		"change": {"actions": ["create"], "after": {"block_public_acls": false, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true}},
	}]}
}

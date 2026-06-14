package main

import rego.v1

test_missing_owner_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "aws_s3_bucket.bad", "type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {"tags": {}}},
	}]}
}

test_owner_present_allowed if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "aws_s3_bucket.ok", "type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {"tags": {"Owner": "team-data"}}},
	}]}
}

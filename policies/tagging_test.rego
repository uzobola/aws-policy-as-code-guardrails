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

test_lambda_missing_owner_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "aws_lambda_function.bad", "type": "aws_lambda_function",
		"change": {"actions": ["create"], "after": {"tags": {}}},
	}]}
}

test_delete_with_null_after_not_denied if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "aws_s3_bucket.gone", "type": "aws_s3_bucket",
		"change": {"actions": ["delete"], "after": null},
	}]}
}

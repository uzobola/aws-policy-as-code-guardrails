package main

import rego.v1

test_wildcard_admin_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "aws_iam_policy.bad", "type": "aws_iam_policy",
		"change": {"actions": ["create"], "after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"}},
	}]}
}

test_scoped_policy_allowed if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "aws_iam_policy.ok", "type": "aws_iam_policy",
		"change": {"actions": ["create"], "after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":\"arn:aws:s3:::data/*\"}]}"}},
	}]}
}

test_inline_role_policy_wildcard_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "aws_iam_role.bad", "type": "aws_iam_role",
		"change": {"actions": ["create"], "after": {"tags": {"Owner": "x"}, "inline_policy": [{"name": "admin", "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"}]}},
	}]}
}

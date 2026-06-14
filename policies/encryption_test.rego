package main

import rego.v1

test_unencrypted_rds_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "aws_db_instance.bad", "type": "aws_db_instance",
		"change": {"actions": ["create"], "after": {"storage_encrypted": false, "tags": {"Owner": "x"}}},
	}]}
}

test_encrypted_rds_allowed if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "aws_db_instance.ok", "type": "aws_db_instance",
		"change": {"actions": ["create"], "after": {"storage_encrypted": true, "tags": {"Owner": "x"}}},
	}]}
}

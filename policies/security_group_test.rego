package main

import rego.v1

test_open_ssh_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "aws_security_group.bad", "type": "aws_security_group",
		"change": {"actions": ["create"], "after": {"tags": {"Owner": "x"}, "ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]}},
	}]}
}

test_restricted_source_allowed if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "aws_security_group.ok", "type": "aws_security_group",
		"change": {"actions": ["create"], "after": {"tags": {"Owner": "x"}, "ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]}]}},
	}]}
}

test_open_ssh_ipv6_denied if {
	count(deny) > 0 with input as {"resource_changes": [{
		"address": "aws_security_group.bad6", "type": "aws_security_group",
		"change": {"actions": ["create"], "after": {"tags": {"Owner": "x"}, "ingress": [{"from_port": 22, "to_port": 22, "ipv6_cidr_blocks": ["::/0"]}]}},
	}]}
}

# Security groups must not expose admin ports to the internet (IPv4 or IPv6).
# NIST 800-53: SC-7 (boundary protection)
package main

import rego.v1

sensitive_ports := {22, 3389}

deny contains msg if {
	some rc in input.resource_changes
	rc.change.after != null
	rc.type == "aws_security_group"
	some ingress in rc.change.after.ingress
	"0.0.0.0/0" in ingress.cidr_blocks
	some port in sensitive_ports
	ingress.from_port <= port
	ingress.to_port >= port
	msg := sprintf("%s: ingress allows 0.0.0.0/0 to port %d; restrict the source CIDR (NIST SC-7)", [rc.address, port])
}

# IPv6: ::/0 is the v6 equivalent of an open internet source and is just as exposed.
deny contains msg if {
	some rc in input.resource_changes
	rc.change.after != null
	rc.type == "aws_security_group"
	some ingress in rc.change.after.ingress
	"::/0" in ingress.ipv6_cidr_blocks
	some port in sensitive_ports
	ingress.from_port <= port
	ingress.to_port >= port
	msg := sprintf("%s: ingress allows ::/0 (IPv6) to port %d; restrict the source CIDR (NIST SC-7)", [rc.address, port])
}

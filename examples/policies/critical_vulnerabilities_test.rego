package compliance_framework.critical_vulnerabilities

test_too_many_critical_vulnerabilities_fail if {
    count(violation) == 1 with input as [
        {
            "state": "open",
            "security_vulnerability": {
                "severity": "critical",
            }
        }
    ]
}

test_few_critical_vulnerabilities_pass if {
    count(violation) == 0 with input as [
        {
            "state": "open",
            "security_vulnerability": {
                "severity": "medium",
            }
        }
    ]
}

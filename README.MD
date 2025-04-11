# Compliance Framework Dependabot Plugin

Fetches dependabot alerts for GitHub repositories, and passes them through the CCF policy engine.

This plugin is intended to be run as part of an aggregate agent, and will execute the policy suite for each repository.

## Authentication

To authenticate this plugin, you must provide a token which has at minimum the following permissions:

* Dependabot Alerts (read-only) - Used for reading alerts
* Administration (read-only) - Used to check whether a repository has alerts enabled

## Integration testing

This plugin contains unit tests as well as integration tests. 

The Integration tests need a GitHub token to call to the GitHub API.

```shell
GITHUB_TOKEN="<TOKEN>" go test ./... -v --tags integration
```

## Policies

When writing OPA / Rego policies for this plugin, they must be added under the `compliance_framework` rego package:

```rego
# deny_critical_severity.rego
# package compliance_framework.[YOUR_RULE_PATH]
package compliance_framework.deny_critical_severity
```

## Releases

This plugin is released using goreleaser to build binaries, and GOOCI to upload artifacts to OCI, 
which will ensure a binary is built for most OS and Architecture combinations. 

You can find the binaries on each release of this plugin in the GitHub releases page.

You can find the OCI implementations in the GitHub Packages page. 

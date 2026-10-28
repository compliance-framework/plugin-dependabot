# Compliance Framework Dependabot Plugin

Fetches dependabot alerts for GitHub repositories, and passes them through the CCF policy engine.

This plugin is intended to be run as part of an aggregate agent, and will execute the policy suite for each repository.

## Authentication

The plugin authenticates with a token (a fine-grained personal access token, for example) or as a
GitHub App installation. Either needs at minimum the following permissions:

* Dependabot Alerts (read-only) - Used for reading alerts
* Administration (read-only) - Used to check whether a repository has alerts enabled

With a token:

```yaml
plugins:
  dependabot:
    config:
      token: "github_pat_..."
      organization: octocat
```

### GitHub App authentication

Instead of a token, the plugin can authenticate as a GitHub App installed on the organization.
Organizations can govern apps centrally, and the plugin only ever holds short-lived
installation tokens, which it renews as they expire.

1. Create a GitHub App (organization *Settings → Developer settings → GitHub Apps*) with the
   read-only repository permissions above, and generate a private key for it.
2. Install the app on the organization, for all repositories or the ones the plugin checks.
3. Configure the plugin with the app's ID, the installation's ID (the number at the end of the
   installation's settings URL) and the private key:

```yaml
plugins:
  dependabot:
    config:
      app_id: "123456"
      installation_id: "78901234"
      # The PEM file the app's "Generate a private key" downloads (preferred), or
      private_key_file: /etc/ccf/github-app.pem
      # the key inline, as PEM or base64-encoded PEM (e.g. from an environment variable)
      # private_key: "LS0tLS1CRUdJTi..."
      organization: octocat
```

A `token`, when set, takes precedence over the app settings. With neither, the plugin calls
GitHub unauthenticated.

The app keys use underscores (unlike `included-repositories` and the other existing keys), so
the agent can fill them from environment variables such as
`CCF_PLUGINS_DEPENDABOT_CONFIG_PRIVATE_KEY`, when the agent's config file declares the key
(for example `private_key: ""`).

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

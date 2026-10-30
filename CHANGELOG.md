# Changelog

## [0.10.0](https://github.com/compliance-framework/plugin-dependabot/compare/v0.9.0...v0.10.0) (2026-10-30)


### Features

* GitHub App authentication ([#35](https://github.com/compliance-framework/plugin-dependabot/issues/35)) ([6ec409e](https://github.com/compliance-framework/plugin-dependabot/commit/6ec409e1d68908ad94beaefeb024e923853292d9))


### Bug Fixes

* **deps:** build with the go1.26.10 toolchain so Renovate can ship Go security fixes ([#37](https://github.com/compliance-framework/plugin-dependabot/issues/37)) ([17e0393](https://github.com/compliance-framework/plugin-dependabot/commit/17e0393e9dcf804fc20cae164dfe0211e70c0669))

## [0.9.0](https://github.com/compliance-framework/plugin-dependabot/compare/v0.8.0...v0.9.0) (2026-10-28)


### ⚠ BREAKING CHANGES

* **deps:** `UsersService.Unsuspend` now takes an `UnsuspendUserRequest` body argument.
    - refactor!: Pass repository creation by value
    ([#&#8203;4616](https://redirect.github.com/google/go-github/issues/4616))
    `RepositoriesService.Create` now requires a
    `CreateRepositoryRequest` value instead of a `*Repository`.
    - refactor!: Rename `LockIssueOptions`,
    `PullRequestBranchUpdateOptions`, and `UserSuspendOptions` to
    `...Request` and pass them by value
    ([#&#8203;4612](https://redirect.github.com/google/go-github/issues/4612))
    `LockIssueOptions`, `PullRequestBranchUpdateOptions`,
    and `UserSuspendOptions` are renamed to `LockIssueRequest`,
    `UpdatePullRequestBranchRequest`, and `SuspendUserRequest` and are
    passed by value to `IssuesService.Lock`,
    `PullRequestsService.UpdateBranch`, and `UsersService.Suspend`;
    `LockIssueRequest.LockReason` is now `*string`.
    - refactor!: Pass the Projects v2 item body types by value and rename
    them to `...Request`
    ([#&#8203;4609](https://redirect.github.com/google/go-github/issues/4609))
    `AddProjectItemOptions` and `UpdateProjectItemOptions`
    are renamed to `AddProjectItemRequest` and `UpdateProjectItemRequest`
    and passed by value; `AddProjectItemRequest.Type` is no longer a
    pointer; `UpdateProjectItemOptions.Archived` is removed.
    - refactor!: Rename `RepositoryCreateForkOptions` and
    `RepositoryAddCollaboratorOptions` to `...Request` and pass them by
    value
    ([#&#8203;4607](https://redirect.github.com/google/go-github/issues/4607))
    `RepositoryCreateForkOptions` and
    `RepositoryAddCollaboratorOptions` are renamed to `CreateForkRequest`
    and `AddCollaboratorRequest`; `RepositoriesService.CreateFork` and
    `RepositoriesService.AddCollaborator` now take them by value instead of
    by pointer; `CreateForkRequest.Organization`, `CreateForkRequest.Name`,
    `CreateForkRequest.DefaultBranchOnly` and
    `AddCollaboratorRequest.Permission` are now pointers.
    - refactor!: Pass the Teams body types by value and rename them to
    `...Request`
    ([#&#8203;4606](https://redirect.github.com/google/go-github/issues/4606))
    `TeamAddTeamMembershipOptions`,
    `TeamAddTeamRepoOptions` and `TeamProjectOptions` are renamed to
    `AddTeamMembershipRequest`, `AddTeamRepoRequest` and
    `AddTeamProjectRequest`; `TeamsService.AddTeamMembershipByID`,
    `AddTeamMembershipBySlug`, `AddTeamRepoByID`, `AddTeamRepoBySlug`,
    `AddTeamProjectByID` and `AddTeamProjectBySlug` now take them by value
    instead of by pointer; `AddTeamMembershipRequest.Role` and
    `AddTeamRepoRequest.Permission` are now `*string`.
    - refactor!: Pass the secret scanning body types by value and rename
    them to `...Request`
    ([#&#8203;4548](https://redirect.github.com/google/go-github/issues/4548))
    `SecretScanningAlertUpdateOptions` and
    `SecretScanningPatternConfigsUpdateOptions` are renamed to
    `UpdateSecretScanningAlertRequest` and
    `UpdateSecretScanningPatternConfigsRequest`;
    `SecretScanningService.UpdateAlert`, `UpdatePatternConfigsForEnterprise`
    and `UpdatePatternConfigsForOrg` now take them by value;
    `UpdateSecretScanningAlertRequest.State` is now `*string`.
    - fix!: Match request body fields to the OpenAPI schemas
    ([#&#8203;4581](https://redirect.github.com/google/go-github/issues/4581))
    Many required request body fields are now passed by
    value.
    - fix!: Send credentials only to configured origins
    ([#&#8203;4564](https://redirect.github.com/google/go-github/issues/4564))
    Credentials are sent only to a client's configured API
    and upload origins — every other destination, including a redirect hop,
    goes out unauthenticated. A request body aimed outside those origins is
    refused. `BasicAuthTransport` and `UnauthenticatedRateLimitedTransport`
    gained `AllowedOrigins`, which GitHub Enterprise users must set.
    - refactor!: Pass org invitation requests by value
    ([#&#8203;4551](https://redirect.github.com/google/go-github/issues/4551))
    `OrganizationsService.CreateOrgInvitation` now takes
    `CreateOrgInvitationRequest` (by value);
    `CreateOrgInvitationRequest.TeamID` is now `TeamIDs`.

### Bug Fixes

* **deps:** bump agent to v0.9.3, workflows to v1.7.0 ([#32](https://github.com/compliance-framework/plugin-dependabot/issues/32)) ([5812704](https://github.com/compliance-framework/plugin-dependabot/commit/5812704c3a1726cc1d2908d2d34406280ef09c31))
* **deps:** bump agent to v0.9.4 ([#34](https://github.com/compliance-framework/plugin-dependabot/issues/34)) ([ec0c0c5](https://github.com/compliance-framework/plugin-dependabot/commit/ec0c0c5a0130cea67d5375728b59a95b6e023940))
* **deps:** update all non-major dependencies ([#30](https://github.com/compliance-framework/plugin-dependabot/issues/30)) ([4083ed0](https://github.com/compliance-framework/plugin-dependabot/commit/4083ed03f4696e652ceff8817ae8e2205e518ff8))
* **deps:** update module github.com/google/go-github/v71 to v93 ([#33](https://github.com/compliance-framework/plugin-dependabot/issues/33)) ([e936da1](https://github.com/compliance-framework/plugin-dependabot/commit/e936da146c421ca6d56a2d2ae847e9e2ac6ae542))

## [0.8.0](https://github.com/compliance-framework/plugin-dependabot/compare/v0.7.0...v0.8.0) (2026-10-14)


### Features

* pass policy data to policy evaluation and depend on agent v0.8.0-rc4 ([b52f66d](https://github.com/compliance-framework/plugin-dependabot/commit/b52f66d62f045735afa6716dc1af886215dbc5fc))


### Bug Fixes

* **deps:** bump agent to v0.9.2 ([#29](https://github.com/compliance-framework/plugin-dependabot/issues/29)) ([6e186d9](https://github.com/compliance-framework/plugin-dependabot/commit/6e186d950647f200384742e8fa06c823dd4a0de0))
* **deps:** bump compliance-framework/agent to v0.9.1 ([#16](https://github.com/compliance-framework/plugin-dependabot/issues/16)) ([576a30d](https://github.com/compliance-framework/plugin-dependabot/commit/576a30d3d8899d666761061086337fcf5a16c205))
* **deps:** update module golang.org/x/crypto to v0.56.0 [security] ([#22](https://github.com/compliance-framework/plugin-dependabot/issues/22)) ([d51f221](https://github.com/compliance-framework/plugin-dependabot/commit/d51f221e8b998b6ad4dd9d6210a23192847c1ec9))
* **deps:** update security fixes (gomod) [security] ([#28](https://github.com/compliance-framework/plugin-dependabot/issues/28)) ([90c7505](https://github.com/compliance-framework/plugin-dependabot/commit/90c75059a6b974594c6a920c3ca56a81eb0e01e3))
* return an error from Init when the plugin is not configured ([#19](https://github.com/compliance-framework/plugin-dependabot/issues/19)) ([232b521](https://github.com/compliance-framework/plugin-dependabot/commit/232b5212c96d7ecf8cf18bfb524776e0f3277926))

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/go-github/v71/github"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/mitchellh/mapstructure"
)

type PluginConfig struct {
	Token            string  `mapstructure:"token"`
	Organization     *string `mapstructure:"organization"`
	User             *string `mapstructure:"user"`
	SecurityTeamName *string `mapstructure:"security-team-name"`
}

type DependabotPlugin struct {
	logger hclog.Logger

	config       *PluginConfig
	githubClient *github.Client
}

type DependabotData struct {
	Alerts              []*github.DependabotAlert
	SecurityTeamMembers []*github.User
}

func (l *DependabotPlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	config := &PluginConfig{}
	mapstructure.Decode(req.GetConfig(), config)
	l.config = config

	l.githubClient = github.NewClient(nil).WithAuthToken(l.config.Token)

	return &proto.ConfigureResponse{}, nil
}

func (l *DependabotPlugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()
	repochan, errchan := l.FetchRepositories(ctx)

	var securityTeamMembers []*github.User
	if l.config.SecurityTeamName != nil && *l.config.SecurityTeamName != "" {
		var err error
		securityTeamMembers, err = l.FetchSecurityTeamMembers(ctx)
		if err != nil {
			return &proto.EvalResponse{
				Status: proto.ExecutionStatus_FAILURE,
			}, err
		}
	}

	done := false
	// Track permission issues during alert collection
	reposAlertsPermissionDenied := make([]string, 0)

	for !done {
		select {
		case err, ok := <-errchan:
			if !ok {
				done = true
				continue
			}
			return &proto.EvalResponse{
				Status: proto.ExecutionStatus_FAILURE,
			}, err
		case repo, ok := <-repochan:
			if !ok {
				done = true
				continue
			}

			alerts, err := l.FetchRepositoryDependabotAlerts(ctx, repo)
			if err != nil {
				if isPermissionError(err) {
					l.logger.Warn("Skipping repository due to insufficient permissions for alerts fetch", "repo", repo.GetFullName(), "error", err)
					reposAlertsPermissionDenied = append(reposAlertsPermissionDenied, repo.GetFullName())
					continue
				}
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}

			data := &DependabotData{
				Alerts: alerts,
			}
			if securityTeamMembers != nil {
				data.SecurityTeamMembers = securityTeamMembers
			}

			evidences, err := l.EvaluatePolicies(ctx, repo, data, req)
			if err != nil {
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}

			if err = apiHelper.CreateEvidence(ctx, evidences); err != nil {
				l.logger.Error("Failed to send evidence", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}
		}
	}

	if len(reposAlertsPermissionDenied) > 0 {
		l.logger.Info("Repositories skipped due to insufficient permissions (alerts)", "count", len(reposAlertsPermissionDenied), "repos", reposAlertsPermissionDenied)
	}

	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, nil
}

func (l *DependabotPlugin) FetchSecurityTeamMembers(ctx context.Context) ([]*github.User, error) {
	members, _, err := l.githubClient.Teams.ListTeamMembersBySlug(ctx, *l.config.Organization, *l.config.SecurityTeamName, nil)
	if err != nil {
		return nil, err
	}
	return members, nil
}

func (l *DependabotPlugin) FetchRepositoryDependabotAlerts(ctx context.Context, repo *github.Repository) ([]*github.DependabotAlert, error) {
	alerts, _, err := l.githubClient.Dependabot.ListRepoAlerts(ctx, repo.GetOwner().GetLogin(), repo.GetName(), &github.ListAlertsOptions{
		ListOptions: github.ListOptions{
			Page:    1,
			PerPage: 100,
		},
		ListCursorOptions: github.ListCursorOptions{},
	})
	return alerts, err
}

func (l *DependabotPlugin) FetchRepositories(ctx context.Context) (<-chan *github.Repository, <-chan error) {
	repositories := make(chan *github.Repository)
	errs := make(chan error)
	go func() {
		defer close(repositories)
		defer close(errs)
		page := 1
		done := false
		// Tracking for logging visibility
		emittedRepos := make([]string, 0)
		noPermissionRepos := make([]string, 0)
		archivedSkipped := 0
		for !done {
			l.logger.Trace("Fetching repositories from Github API")
			repos, _, err := l.githubClient.Repositories.ListByOrg(ctx, *l.config.Organization, &github.RepositoryListByOrgOptions{
				ListOptions: github.ListOptions{
					Page: page,
				},
			})
			if err != nil {
				l.logger.Error("Failed while fetching repositories from Github API")
				errs <- err
				done = true
				break
			}
			for _, repo := range repos {
				if repo.GetArchived() {
					archivedSkipped++
					continue
				}

				alertsEnabled, _, err := l.githubClient.Repositories.GetVulnerabilityAlerts(ctx, repo.GetOwner().GetLogin(), repo.GetName())
				if err != nil {
					if isPermissionError(err) {
						l.logger.Warn("Skipping repository due to insufficient permissions for vulnerability alerts check", "repo", repo.GetFullName(), "error", err)
						noPermissionRepos = append(noPermissionRepos, repo.GetFullName())
						continue
					}
					errs <- err
					done = true
					break
				}
				if alertsEnabled {
					repositories <- repo
					emittedRepos = append(emittedRepos, repo.GetFullName())
				}
			}
			page++
			if len(repos) == 0 {
				done = true
				break
			}
		}
		// Emit a summary for engineers to understand visibility
		l.logger.Info("Repository enumeration summary", "emitted", len(emittedRepos), "skipped_permissions", len(noPermissionRepos), "skipped_archived", archivedSkipped)
		if len(emittedRepos) > 0 {
			l.logger.Debug("Repositories with sufficient permissions (and alerts enabled)", "repos", emittedRepos)
		}
		if len(noPermissionRepos) > 0 {
			l.logger.Info("Repositories without sufficient permissions", "repos", noPermissionRepos)
		}
	}()
	return repositories, errs
}

func (l *DependabotPlugin) EvaluatePolicies(ctx context.Context, repo *github.Repository, data *DependabotData, req *proto.EvalRequest) ([]*proto.Evidence, error) {
	var accumulatedErrors error

	activities := make([]*proto.Activity, 0)
	evidences := make([]*proto.Evidence, 0)
	activities = append(activities, &proto.Activity{
		Title: "Collect Repository Dependabot Alerts",
	})
	actors := []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework"),
				},
			},
			Props: nil,
		},
		{
			Title: "Continuous Compliance Framework - Dependabot Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-dependabot",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework Dependabot Plugin"),
				},
			},
			Props: nil,
		},
	}
	components := []*proto.Component{
		{
			Identifier:  "common-components/github-repository",
			Type:        "service",
			Title:       "GitHub Repository",
			Description: "A GitHub repository is a discrete codebase or project workspace hosted within a GitHub Organization or user account. It contains source code, documentation, configuration files, workflows, and version history managed through Git. Repositories support access control, issues, pull requests, branch protection, and automated CI/CD pipelines.",
			Purpose:     "To serve as the authoritative and version-controlled location for a specific software project, enabling secure collaboration, code review, automation, and traceability of changes throughout the development lifecycle.",
		},
		{
			Identifier:  "common-components/version-control",
			Type:        "service",
			Title:       "Version Control",
			Description: "Version control systems track and manage changes to source code and configuration files over time. They provide collaboration, traceability, and the ability to audit or revert code to previous states. Version control enables parallel development workflows and structured release management across software projects.",
			Purpose:     "To maintain a complete and auditable history of code and configuration changes, enable collaboration across distributed teams, and support secure and traceable software development lifecycle (SDLC) practices.",
		},
	}
	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("github-repository/%s", repo.GetFullName()),
			Type:       "github-repository",
			Title:      fmt.Sprintf("Github Repository [%s]", repo.GetName()),
			Props: []*proto.Property{
				{
					Name:  "name",
					Value: repo.GetName(),
				},
				{
					Name:  "path",
					Value: repo.GetFullName(),
				},
				{
					Name:  "organization",
					Value: repo.GetOwner().GetName(),
				},
			},
			Links: []*proto.Link{
				{
					Href: repo.GetURL(),
					Text: policyManager.Pointer("Repository URL"),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: "common-components/github-repository",
				},
				{
					Identifier: "common-components/version-control",
				},
			},
		},
	}
	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("github-repository/%s", repo.GetFullName()),
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("github-organization/%s", repo.GetOwner().GetLogin()),
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/github-repository",
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/version-control",
		},
	}

	for _, policyPath := range req.GetPolicyPaths() {
		// Explicitly reset steps to make things readable
		processor := policyManager.NewPolicyProcessor(
			l.logger,
			map[string]string{
				"provider":     "github",
				"type":         "repository",
				"repository":   repo.GetName(),
				"organization": repo.GetOwner().GetLogin(),
			},
			subjects,
			components,
			inventory,
			actors,
			activities,
		)
		evidence, err := processor.GenerateResults(ctx, policyPath, data)
		evidences = slices.Concat(evidences, evidence)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, err)
		}
	}

	l.logger.Info("collected evidence", "count", len(evidences))

	return evidences, accumulatedErrors
}

// isPermissionError returns true if the error from the GitHub client indicates
// a permissions or visibility issue (e.g., 401/403/404).
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	var ger *github.ErrorResponse
	if errors.As(err, &ger) {
		if ger.Response != nil {
			switch ger.Response.StatusCode {
			case 401, 403, 404:
				return true
			}
		}
	}
	return false
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	dependabot := &DependabotPlugin{
		logger: logger,
	}
	// pluginMap is the map of plugins we can dispense.
	logger.Debug("initiating dependabot plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: dependabot,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}

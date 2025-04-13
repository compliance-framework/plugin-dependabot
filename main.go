package main

import (
	"context"
	"errors"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/go-github/v71/github"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/mitchellh/mapstructure"
	"slices"
)

type PluginConfig struct {
	Token        string  `mapstructure:"token"`
	Organization *string `mapstructure:"organization"`
	User         *string `mapstructure:"user"`
}

type DependabotPlugin struct {
	logger hclog.Logger
	data   map[string]interface{}
	config *PluginConfig

	githubClient *github.Client
}

func (l *DependabotPlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	//l.config = req.GetConfig()
	config := &PluginConfig{}
	mapstructure.Decode(req.GetConfig(), config)
	l.config = config

	l.githubClient = github.NewClient(nil).WithAuthToken(l.config.Token)

	return &proto.ConfigureResponse{}, nil
}

func (l *DependabotPlugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()
	repochan, errchan := l.FetchRepositories(ctx)
	done := false
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
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}

			observations, findings, err := l.EvaluatePolicies(ctx, repo, alerts, req)
			if err != nil {
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}

			if err = apiHelper.CreateObservations(ctx, observations); err != nil {
				l.logger.Error("Failed to send observations", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}

			if err = apiHelper.CreateFindings(ctx, findings); err != nil {
				l.logger.Error("Failed to send findings", "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}
		}
	}

	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, nil
}

func (l *DependabotPlugin) FetchRepositoryDependabotAlerts(ctx context.Context, repo *github.Repository) ([]*github.DependabotAlert, error) {
	alerts, _, err := l.githubClient.Dependabot.ListRepoAlerts(ctx, repo.GetOwner().GetLogin(), repo.GetName(), &github.ListAlertsOptions{
		ListOptions: github.ListOptions{
			Page:    1,
			PerPage: 200,
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
				alertsEnabled, _, err := l.githubClient.Repositories.GetVulnerabilityAlerts(ctx, repo.GetOwner().GetLogin(), repo.GetName())
				if err != nil {
					errs <- err
					done = true
					break
				}
				if !repo.GetArchived() && alertsEnabled {
					repositories <- repo
				}
			}
			page++
			if len(repos) == 0 {
				done = true
				break
			}
		}
	}()
	return repositories, errs
}

func (l *DependabotPlugin) EvaluatePolicies(ctx context.Context, repo *github.Repository, alerts []*github.DependabotAlert, req *proto.EvalRequest) ([]*proto.Observation, []*proto.Finding, error) {
	var accumulatedErrors error

	activities := make([]*proto.Activity, 0)
	findings := make([]*proto.Finding, 0)
	observations := make([]*proto.Observation, 0)
	activities = append(activities, &proto.Activity{
		Title: "Collect Repository Dependabot Alerts",
	})
	subjects := []*proto.SubjectReference{
		{
			Type: "software-repository",
			Attributes: map[string]string{
				"provider":        "github",
				"type":            "repository",
				"repository-name": repo.GetName(),
				"organization":    repo.GetOwner().GetLogin(),
				"url":             repo.GetURL(),
			},
			Title: policyManager.Pointer("Software Repository"),
			Props: []*proto.Property{
				{
					Name:  "repository",
					Value: repo.GetFullName(),
				},
			},
			Links: []*proto.Link{
				{
					Href: repo.GetURL(),
					Text: policyManager.Pointer("Repository URL"),
				},
			},
		},
		{
			Type: "software-organization",
			Attributes: map[string]string{
				"provider":          "github",
				"type":              "organization",
				"organization-name": repo.GetOrganization().GetName(),
				"organization-path": repo.GetOrganization().GetLogin(),
			},
			Title: policyManager.Pointer("Software Organization"),
			Props: []*proto.Property{
				{
					Name:  "organization",
					Value: repo.GetOrganization().GetName(),
				},
			},
			Links: []*proto.Link{
				{
					Href: repo.GetOrganization().GetURL(),
					Text: policyManager.Pointer("Organization URL"),
				},
			},
		},
	}
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
			Title: "Continuous Compliance Framework - Local SSH Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-local-ssh",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework' Local SSH Plugin"),
				},
			},
			Props: nil,
		},
	}
	components := []*proto.ComponentReference{
		{
			Identifier: "common-components/github-repository",
		},
		{
			Identifier: "common-components/software-repository",
		},
		{
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
				"repository":   repo.GetFullName(),
				"_policy_path": policyPath,
			},
			subjects,
			components,
			actors,
			activities,
		)
		obs, finds, err := processor.GenerateResults(ctx, policyPath, alerts)
		observations = slices.Concat(observations, obs)
		findings = slices.Concat(findings, finds)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, err)
		}
	}

	l.logger.Info("collected observations", "count", len(observations))
	l.logger.Info("collected findings", "count", len(findings))

	return observations, findings, accumulatedErrors
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

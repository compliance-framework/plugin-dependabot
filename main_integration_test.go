//go:build integration

package main

import (
	"context"
	"os"
	"testing"

	policy_manager "github.com/compliance-framework/agent/policy-manager"
	"github.com/google/go-github/v71/github"
	"github.com/hashicorp/go-hclog"
)

func TestDependabotPlugin_Integration_FetchRepositories(t *testing.T) {
	ctx := context.Background()

	plugin := DependabotPlugin{
		logger: hclog.NewNullLogger(),
		config: &PluginConfig{
			Token:        os.Getenv("GITHUB_TOKEN"),
			Organization: policy_manager.Pointer("compliance-framework"),
		},
		githubClient: github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_TOKEN")),
	}

	repochan, errchan := plugin.FetchRepositories(ctx)
	done := false
	counter := 0

	for counter < 5 && !done {
		counter++
		select {
		case err, ok := <-errchan:
			if !ok {
				done = true
				continue
			}
			t.Error(err)
		case _, ok := <-repochan:
			if !ok {
				done = true
				continue
			}
			counter++
		}
	}

	t.Log("Successfully collected repositories", counter)
}

func TestDependabotPlugin_Integration_FetchRepositoryDependabotAlerts(t *testing.T) {
	ctx := context.Background()

	plugin := DependabotPlugin{
		logger: hclog.New(&hclog.LoggerOptions{
			Level:      hclog.Trace,
			JSONFormat: true,
		}),
		config: &PluginConfig{
			Token:        os.Getenv("GITHUB_TOKEN"),
			Organization: policy_manager.Pointer("compliance-framework"),
		},
		githubClient: github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_TOKEN")),
	}

	repo, _, err := plugin.githubClient.Repositories.Get(ctx, "compliance-framework", "configuration-service")
	if err != nil {
		t.Error(err)
	}

	alerts, err := plugin.FetchRepositoryDependabotAlerts(ctx, repo)
	if err != nil {
		t.Error(err)
	}

	t.Log("Successfully collected alerts", len(alerts))
}

func TestDependabotPlugin_Integration_FetchTeamMembers(t *testing.T) {
	ctx := context.Background()

	plugin := DependabotPlugin{
		logger: hclog.NewNullLogger(),
		config: &PluginConfig{
			Token:            os.Getenv("GITHUB_TOKEN"),
			Organization:     policy_manager.Pointer("compliance-framework"),
			SecurityTeamName: policy_manager.Pointer("security"),
		},
		githubClient: github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_TOKEN")),
	}

	members, err := plugin.FetchSecurityTeamMembers(ctx)
	if err != nil {
		t.Error(err)
	}
	t.Log("Successfully collected securtiy team members", members)
}

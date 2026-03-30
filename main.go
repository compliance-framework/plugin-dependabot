package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/go-github/v71/github"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/mitchellh/mapstructure"
)

type OperationalMode string

const (
	OperationalModeBundled  OperationalMode = "Bundled"  // default: one evidence per repo
	OperationalModeGranular OperationalMode = "Granular" // one evidence per alert/CVE
)

type PluginConfig struct {
	Token                string          `mapstructure:"token"`
	Organization         *string         `mapstructure:"organization"`
	IncludedRepositories *string         `mapstructure:"included-repositories"`
	User                 *string         `mapstructure:"user"`
	SecurityTeamName     *string         `mapstructure:"security-team-name"`
	OperationalMode      OperationalMode `mapstructure:"operational-mode"`
}
type ParsedConfig struct {
	Token                string          `mapstructure:"token"`
	Organization         *string         `mapstructure:"organization"`
	IncludedRepositories []string        `mapstructure:"included-repositories"`
	User                 *string         `mapstructure:"user"`
	SecurityTeamName     *string         `mapstructure:"security-team-name"`
	OperationalMode      OperationalMode `mapstructure:"operational-mode"`
}
type DependabotPlugin struct {
	logger hclog.Logger

	config       *PluginConfig
	parsedConfig *ParsedConfig
	githubClient *github.Client
}

type DependabotData struct {
	Alerts              []*github.DependabotAlert
	SecurityTeamMembers []*github.User
}

var errDependabotAlertsPermissionDenied = errors.New("insufficient permissions to fetch dependabot alerts")

var (
	granularActivities = []*proto.Activity{
		{Title: "Collect Individual Dependabot Alert"},
	}
	granularActors = []*proto.OriginActor{
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
		},
	}
	granularComponents = []*proto.Component{
		{
			Identifier:  "common-components/github-repository",
			Type:        "service",
			Title:       "GitHub Repository",
			Description: "A GitHub repository is a discrete codebase or project workspace hosted within a GitHub Organization or user account.",
			Purpose:     "To serve as the authoritative and version-controlled location for a specific software project.",
		},
	}
)

type granularPolicyContext struct {
	labelsBase map[string]string
	inventory  []*proto.InventoryItem
	subjects   []*proto.Subject
}

func (l *DependabotPlugin) ParseConfig() {
	l.parsedConfig = &ParsedConfig{}
	if l.config.IncludedRepositories != nil {
		l.parsedConfig.IncludedRepositories = strings.Split(*l.config.IncludedRepositories, ",")
	}
	l.parsedConfig.Token = l.config.Token
	l.parsedConfig.Organization = l.config.Organization
	l.parsedConfig.User = l.config.User
	l.parsedConfig.SecurityTeamName = l.config.SecurityTeamName
	switch strings.ToLower(string(l.config.OperationalMode)) {
	case strings.ToLower(string(OperationalModeGranular)):
		l.parsedConfig.OperationalMode = OperationalModeGranular
	case strings.ToLower(string(OperationalModeBundled)):
		l.parsedConfig.OperationalMode = OperationalModeBundled
	default:
		l.logger.Debug("ParseConfig: operational-mode not set or unrecognised, defaulting to Bundled", "raw_value", l.config.OperationalMode)
		l.parsedConfig.OperationalMode = OperationalModeBundled
	}
	l.logger.Debug("ParseConfig: resolved operational mode",
		"raw_value", l.config.OperationalMode,
		"resolved_value", l.parsedConfig.OperationalMode,
		"included_repositories", l.parsedConfig.IncludedRepositories,
	)
}

func (l *DependabotPlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	config := &PluginConfig{}
	if err := mapstructure.Decode(req.GetConfig(), config); err != nil {
		l.logger.Error("Configure: failed to decode config", "error", err)
		return nil, err
	}
	l.config = config
	l.logger.Debug("Configure: received raw config",
		"operational_mode", l.config.OperationalMode,
		"organization", l.config.Organization,
		"included_repositories", l.config.IncludedRepositories,
		"security_team_name", l.config.SecurityTeamName,
	)

	l.ParseConfig()
	l.githubClient = github.NewClient(nil).WithAuthToken(l.parsedConfig.Token)

	return &proto.ConfigureResponse{}, nil
}

func (l *DependabotPlugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	ctx := context.Background()
	l.logger.Debug("Init: starting with operational mode", "operational_mode", l.parsedConfig.OperationalMode)

	subjectTemplates := []*proto.SubjectTemplate{
		{
			Name:                "dependabot-repository",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       "Dependabot for repository: {{ .repository }}",
			DescriptionTemplate: "Dependabot alerts for GitHub repository {{ .repository }} in organization {{ .organization }}",
			PurposeTemplate:     "Represents Dependabot monitoring for a GitHub repository being evaluated for compliance",
			IdentityLabelKeys:   []string{"repository", "organization"},
			SelectorLabels:      []*proto.SubjectLabelSelector{},
			LabelSchema: []*proto.SubjectLabelSchema{
				{Key: "repository", Description: "The name of the GitHub repository"},
				{Key: "organization", Description: "The GitHub organization owning the repository"},
			},
		},
	}

	return runner.InitWithSubjectsAndRisksFromPolicies(ctx, l.logger, req, apiHelper, subjectTemplates)
}

func (l *DependabotPlugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.Background()
	l.logger.Debug("Eval: starting", "operational_mode", l.parsedConfig.OperationalMode, "policy_paths", req.GetPolicyPaths())
	repochan, errchan := l.FetchRepositories(ctx)
	l.logger.Debug("Fetching repositories from Github API")
	var securityTeamMembers []*github.User
	if l.parsedConfig.SecurityTeamName != nil && *l.parsedConfig.SecurityTeamName != "" {
		var err error
		securityTeamMembers, err = l.FetchSecurityTeamMembers(ctx)
		if err != nil {
			l.logger.Error("Failed to fetch security team members from Github API", "error", err)
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
			l.logger.Debug("Error fetching repositories from Github API", "error", err)
			return &proto.EvalResponse{
				Status: proto.ExecutionStatus_FAILURE,
			}, err
		case repo, ok := <-repochan:
			if !ok {
				done = true
				continue
			}
			l.logger.Debug("Fetching repository dependabot alerts from Github API", "repo", repo.GetFullName())
			alerts, err := l.FetchRepositoryDependabotAlerts(ctx, repo)
			if err != nil {
				if errors.Is(err, errDependabotAlertsPermissionDenied) {
					l.logger.Warn("Skipping repository due to insufficient permissions for alerts fetch", "repo", repo.GetFullName(), "error", err)
					reposAlertsPermissionDenied = append(reposAlertsPermissionDenied, repo.GetFullName())
					continue
				}
				l.logger.Error("Failed to fetch repository dependabot alerts from Github API", "repo", repo.GetFullName(), "error", err)
				return &proto.EvalResponse{
					Status: proto.ExecutionStatus_FAILURE,
				}, err
			}

			l.logger.Debug("Eval: dispatching repo",
				"repo", repo.GetFullName(),
				"operational_mode", l.parsedConfig.OperationalMode,
				"operational_mode_bytes", fmt.Sprintf("%q", string(l.parsedConfig.OperationalMode)),
				"is_granular", l.parsedConfig.OperationalMode == OperationalModeGranular,
			)
			switch l.parsedConfig.OperationalMode {
			case OperationalModeGranular:
				l.logger.Debug("Eval: using granular path", "repo", repo.GetFullName())
				if err := l.evalForGranular(ctx, repo, alerts, req, apiHelper); err != nil {
					return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
				}
			default:
				l.logger.Debug("Eval: using bundle path", "repo", repo.GetFullName())
				if err := l.evalForBundle(ctx, repo, alerts, securityTeamMembers, req, apiHelper); err != nil {
					return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
				}
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

func (l *DependabotPlugin) evalForGranular(ctx context.Context, repo *github.Repository, alerts []*github.DependabotAlert, req *proto.EvalRequest, apiHelper runner.ApiHelper) error {
	l.logger.Debug("evalForGranular: starting", "repo", repo.GetFullName(), "alert_count", len(alerts), "policy_paths", req.GetPolicyPaths())
	policyContext := newGranularPolicyContext(repo)
	totalEvidence := 0
	for i, alert := range alerts {
		cveID := granularAlertIdentifier(alert)
		l.logger.Debug("evalForGranular: evaluating alert", "index", i, "cve_id", cveID, "state", alert.GetState())
		alertEvidences, err := l.EvaluateGranularPolicies(ctx, repo, alert, req, policyContext)
		if err != nil {
			l.logger.Error("Failed to evaluate granular policies", "repo", repo.GetFullName(), "cve_id", cveID, "error", err)
			return err
		}
		l.logger.Debug("evalForGranular: evidence produced", "cve_id", cveID, "count", len(alertEvidences))
		totalEvidence += len(alertEvidences)
		if err = apiHelper.CreateEvidence(ctx, alertEvidences); err != nil {
			l.logger.Error("Failed to send granular evidence", "repo", repo.GetFullName(), "cve_id", cveID, "error", err)
			return err
		}
		l.logger.Debug("evalForGranular: evidence sent", "cve_id", cveID)
	}
	l.logger.Info("Granular evaluation summary", "repo", repo.GetFullName(), "alert_count", len(alerts), "evidence_count", totalEvidence)
	return nil
}

func (l *DependabotPlugin) evalForBundle(ctx context.Context, repo *github.Repository, alerts []*github.DependabotAlert, securityTeamMembers []*github.User, req *proto.EvalRequest, apiHelper runner.ApiHelper) error {
	l.logger.Debug("evalForBundle: starting", "repo", repo.GetFullName(), "alert_count", len(alerts), "policy_paths", req.GetPolicyPaths())
	data := &DependabotData{
		Alerts: alerts,
	}
	if securityTeamMembers != nil {
		data.SecurityTeamMembers = securityTeamMembers
	}

	evidences, err := l.EvaluatePolicies(ctx, repo, data, req)
	if err != nil {
		l.logger.Error("Failed to evaluate policies", "repo", repo.GetFullName(), "error", err)
		return err
	}
	l.logger.Debug("evalForBundle: evidence produced", "repo", repo.GetFullName(), "count", len(evidences))

	if err = apiHelper.CreateEvidence(ctx, evidences); err != nil {
		l.logger.Error("Failed to send evidence", "repo", repo.GetFullName(), "error", err)
		return err
	}
	l.logger.Debug("evalForBundle: evidence sent", "repo", repo.GetFullName())
	return nil
}

func (l *DependabotPlugin) FetchSecurityTeamMembers(ctx context.Context) ([]*github.User, error) {
	members, _, err := l.githubClient.Teams.ListTeamMembersBySlug(ctx, *l.parsedConfig.Organization, *l.parsedConfig.SecurityTeamName, nil)
	if err != nil {
		if isPermissionError(err) {
			return nil, nil
		}
		return nil, err
	}
	return members, nil
}

func (l *DependabotPlugin) FetchRepositoryDependabotAlerts(ctx context.Context, repo *github.Repository) ([]*github.DependabotAlert, error) {
	alerts, _, err := l.githubClient.Dependabot.ListRepoAlerts(ctx, repo.GetOwner().GetLogin(), repo.GetName(), &github.ListAlertsOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
		ListCursorOptions: github.ListCursorOptions{},
	})
	if isPermissionError(err) {
		return nil, fmt.Errorf("%w: %s: %w", errDependabotAlertsPermissionDenied, repo.GetFullName(), err)
	}
	l.logger.Debug("Fetched repository dependabot alerts from Github API", "repo", repo.GetFullName(), "count", len(alerts))
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
			repos, _, err := l.githubClient.Repositories.ListByOrg(ctx, *l.parsedConfig.Organization, &github.RepositoryListByOrgOptions{
				ListOptions: github.ListOptions{
					Page: page,
				},
			})
			if err != nil {
				l.logger.Error("Failed while fetching repositories from Github API", "error", err)
				errs <- err
				done = true
				break
			}
			for _, repo := range repos {
				if repo.GetArchived() {
					l.logger.Debug("Skipping archived repository", "repo", repo.GetFullName())
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
					l.logger.Error("Failed while fetching vulnerability alerts from Github API", "repo", repo.GetFullName(), "error", err)
					errs <- err
					done = true
					break
				}
				if alertsEnabled {
					if l.parsedConfig.IncludedRepositories != nil {
						if !slices.Contains(l.parsedConfig.IncludedRepositories, repo.GetFullName()) {
							l.logger.Debug("Skipping repository due to not being explicitly included in config", "repo", repo.GetFullName())
							continue
						}
					}
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
			Title:      fmt.Sprintf("GitHub Repository [%s]", repo.GetName()),
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
					Value: repo.GetOwner().GetLogin(),
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
		l.logger.Debug("EvaluatePolicies: running policy", "repo", repo.GetFullName(), "policy_path", policyPath)
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
		if l.logger.IsTrace() {
			if inputJSON, jsonErr := json.Marshal(data); jsonErr == nil {
				l.logger.Trace("EvaluatePolicies: policy input", "policy_path", policyPath, "input", string(inputJSON))
			} else {
				l.logger.Trace("EvaluatePolicies: failed to marshal policy input", "policy_path", policyPath, "error", jsonErr)
			}
		}
		evidence, err := processor.GenerateResults(ctx, policyPath, data)
		l.logger.Debug("EvaluatePolicies: policy result", "policy_path", policyPath, "evidence_count", len(evidence), "error", err)
		evidences = slices.Concat(evidences, evidence)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, err)
		}
	}

	l.logger.Info("collected evidence", "count", len(evidences))

	return evidences, accumulatedErrors
}

func (l *DependabotPlugin) EvaluateGranularPolicies(ctx context.Context, repo *github.Repository, alert *github.DependabotAlert, req *proto.EvalRequest, policyContext *granularPolicyContext) ([]*proto.Evidence, error) {
	var accumulatedErrors error

	labels := buildGranularPolicyLabels(policyContext.labelsBase, alert)
	cveID := labels["cve_id"]

	evidences := make([]*proto.Evidence, 0)
	for _, policyPath := range req.GetPolicyPaths() {
		l.logger.Debug("EvaluateGranularPolicies: running policy", "cve_id", cveID, "repo", repo.GetFullName(), "policy_path", policyPath)
		processor := policyManager.NewPolicyProcessor(
			l.logger,
			labels,
			policyContext.subjects,
			granularComponents,
			policyContext.inventory,
			granularActors,
			granularActivities,
		)
		if l.logger.IsTrace() {
			if inputJSON, jsonErr := json.Marshal(alert); jsonErr == nil {
				l.logger.Trace("EvaluateGranularPolicies: policy input", "cve_id", cveID, "policy_path", policyPath, "input", string(inputJSON))
			} else {
				l.logger.Trace("EvaluateGranularPolicies: failed to marshal policy input", "cve_id", cveID, "policy_path", policyPath, "error", jsonErr)
			}
		}
		evidence, err := processor.GenerateResults(ctx, policyPath, granularPolicyInput(alert))
		l.logger.Debug("EvaluateGranularPolicies: policy result", "cve_id", cveID, "policy_path", policyPath, "evidence_count", len(evidence), "error", err)
		evidences = slices.Concat(evidences, evidence)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, err)
		}
	}

	l.logger.Debug("collected granular evidence", "cve_id", cveID, "repo", repo.GetFullName(), "count", len(evidences))

	return evidences, accumulatedErrors
}

func newGranularPolicyContext(repo *github.Repository) *granularPolicyContext {
	repositoryIdentifier := fmt.Sprintf("github-repository/%s", repo.GetFullName())
	return &granularPolicyContext{
		labelsBase: map[string]string{
			"provider":     "github",
			"type":         "dependabot",
			"repository":   repo.GetName(),
			"organization": repo.GetOwner().GetLogin(),
		},
		inventory: []*proto.InventoryItem{
			{
				Identifier: repositoryIdentifier,
				Type:       "github-repository",
				Title:      fmt.Sprintf("GitHub Repository [%s]", repo.GetName()),
				Props: []*proto.Property{
					{Name: "name", Value: repo.GetName()},
					{Name: "path", Value: repo.GetFullName()},
					{Name: "organization", Value: repo.GetOwner().GetLogin()},
				},
				Links: []*proto.Link{
					{
						Href: repo.GetURL(),
						Text: policyManager.Pointer("Repository URL"),
					},
				},
				ImplementedComponents: []*proto.InventoryItemImplementedComponent{
					{Identifier: "common-components/github-repository"},
				},
			},
		},
		subjects: []*proto.Subject{
			{
				Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
				Identifier: repositoryIdentifier,
			},
			{
				Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
				Identifier: fmt.Sprintf("github-organization/%s", repo.GetOwner().GetLogin()),
			},
			{
				Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
				Identifier: "common-components/github-repository",
			},
		},
	}
}

func buildGranularPolicyLabels(baseLabels map[string]string, alert *github.DependabotAlert) map[string]string {
	severity := alert.GetSecurityVulnerability().GetSeverity()
	impact := severity
	if severity == "medium" {
		impact = "moderate"
	}

	var cvssScoreVal float64
	if score := alert.GetSecurityAdvisory().GetCVSS().GetScore(); score != nil {
		cvssScoreVal = *score
	}

	labels := make(map[string]string, len(baseLabels)+6)
	for key, value := range baseLabels {
		labels[key] = value
	}
	labels["cve_id"] = granularAlertIdentifier(alert)
	labels["package_name"] = alert.GetDependency().GetPackage().GetName()
	labels["ecosystem"] = alert.GetDependency().GetPackage().GetEcosystem()
	labels["severity"] = severity
	labels["impact"] = impact
	labels["cvss_score"] = fmt.Sprintf("%.1f", cvssScoreVal)
	return labels
}

func granularAlertIdentifier(alert *github.DependabotAlert) string {
	cveID := alert.GetSecurityAdvisory().GetCVEID()
	if cveID == "" {
		cveID = alert.GetSecurityAdvisory().GetGHSAID()
	}
	return cveID
}

func granularPolicyInput(alert *github.DependabotAlert) []*github.DependabotAlert {
	return []*github.DependabotAlert{alert}
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
			"runner": &runner.RunnerV2GRPCPlugin{
				Impl: dependabot,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}

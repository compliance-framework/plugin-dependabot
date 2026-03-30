package main

import (
	"context"
	"errors"
	"testing"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/go-github/v71/github"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// mockApiHelper implements runner.ApiHelper for unit tests.
type mockApiHelper struct {
	createEvidenceErr   error
	createEvidenceCalls int
}

func (m *mockApiHelper) CreateEvidence(_ context.Context, _ []*proto.Evidence) error {
	m.createEvidenceCalls++
	return m.createEvidenceErr
}

func (m *mockApiHelper) UpsertRiskTemplates(_ context.Context, _ string, _ []*proto.RiskTemplate) error {
	return nil
}

func (m *mockApiHelper) UpsertSubjectTemplates(_ context.Context, _ []*proto.SubjectTemplate) error {
	return nil
}

// ptr returns a pointer to s, useful for building github objects in tests.
func ptr(s string) *string { return &s }

// DependabotPluginSuite holds shared helpers for all plugin unit tests.
type DependabotPluginSuite struct {
	suite.Suite
}

func TestDependabotPluginSuite(t *testing.T) {
	suite.Run(t, new(DependabotPluginSuite))
}

func (s *DependabotPluginSuite) newPlugin(mode OperationalMode) *DependabotPlugin {
	org := "test-org"
	return &DependabotPlugin{
		logger: hclog.NewNullLogger(),
		parsedConfig: &ParsedConfig{
			Organization:    &org,
			OperationalMode: mode,
		},
	}
}

func (s *DependabotPluginSuite) newRepo() *github.Repository {
	return &github.Repository{
		Name:     ptr("test-repo"),
		FullName: ptr("test-org/test-repo"),
		Owner: &github.User{
			Login: ptr("test-org"),
			Name:  ptr("test-org"),
		},
		URL: ptr("https://github.com/test-org/test-repo"),
	}
}

func (s *DependabotPluginSuite) newAlert() *github.DependabotAlert {
	return &github.DependabotAlert{}
}

func (s *DependabotPluginSuite) newDetailedAlert(cveID, ghsaID, severity, packageName, ecosystem string, cvssScore *float64) *github.DependabotAlert {
	return &github.DependabotAlert{
		State: ptr("open"),
		Dependency: &github.Dependency{
			Package: &github.VulnerabilityPackage{
				Name:      ptr(packageName),
				Ecosystem: ptr(ecosystem),
			},
		},
		SecurityAdvisory: &github.DependabotSecurityAdvisory{
			CVEID:  ptr(cveID),
			GHSAID: ptr(ghsaID),
			CVSS: &github.AdvisoryCVSS{
				Score: cvssScore,
			},
		},
		SecurityVulnerability: &github.AdvisoryVulnerability{
			Severity: ptr(severity),
		},
	}
}

// --- evalForGranular ---

func (s *DependabotPluginSuite) TestEvalForGranular_NoAlerts() {
	plugin := s.newPlugin(OperationalModeGranular)
	helper := &mockApiHelper{}

	err := plugin.evalForGranular(context.Background(), s.newRepo(), nil, &proto.EvalRequest{}, helper)

	require.NoError(s.T(), err)
	assert.Equal(s.T(), 0, helper.createEvidenceCalls)
}

func (s *DependabotPluginSuite) TestEvalForGranular_NoPolicyPathsSkipsCreateEvidence() {
	plugin := s.newPlugin(OperationalModeGranular)
	helper := &mockApiHelper{}
	alerts := []*github.DependabotAlert{s.newAlert(), s.newAlert(), s.newAlert()}

	err := plugin.evalForGranular(context.Background(), s.newRepo(), alerts, &proto.EvalRequest{}, helper)

	require.NoError(s.T(), err)
	assert.Equal(s.T(), 0, helper.createEvidenceCalls)
}

func (s *DependabotPluginSuite) TestEvalForGranular_NoPolicyPathsDoNotSurfaceCreateEvidenceErrors() {
	plugin := s.newPlugin(OperationalModeGranular)
	wantErr := errors.New("api unavailable")
	helper := &mockApiHelper{createEvidenceErr: wantErr}

	err := plugin.evalForGranular(context.Background(), s.newRepo(), []*github.DependabotAlert{s.newAlert()}, &proto.EvalRequest{}, helper)

	require.NoError(s.T(), err)
	assert.Equal(s.T(), 0, helper.createEvidenceCalls)
}

func (s *DependabotPluginSuite) TestEvalForGranular_NoPolicyPathsSkipAllNoOpApiCalls() {
	plugin := s.newPlugin(OperationalModeGranular)
	helper := &mockApiHelper{createEvidenceErr: errors.New("fail")}
	alerts := []*github.DependabotAlert{s.newAlert(), s.newAlert(), s.newAlert()}

	err := plugin.evalForGranular(context.Background(), s.newRepo(), alerts, &proto.EvalRequest{}, helper)

	require.NoError(s.T(), err)
	assert.Equal(s.T(), 0, helper.createEvidenceCalls)
}

// --- evalForBundle ---

func (s *DependabotPluginSuite) TestEvalForBundle_CallsCreateEvidenceOnce() {
	plugin := s.newPlugin(OperationalModeBundled)
	helper := &mockApiHelper{}

	// no policy paths → EvaluatePolicies returns empty evidence without invoking OPA
	err := plugin.evalForBundle(context.Background(), s.newRepo(), nil, nil, &proto.EvalRequest{}, helper)

	require.NoError(s.T(), err)
	assert.Equal(s.T(), 1, helper.createEvidenceCalls)
}

func (s *DependabotPluginSuite) TestEvalForBundle_WithSecurityTeamMembers() {
	plugin := s.newPlugin(OperationalModeBundled)
	helper := &mockApiHelper{}
	members := []*github.User{{Login: ptr("security-bot")}}

	err := plugin.evalForBundle(context.Background(), s.newRepo(), nil, members, &proto.EvalRequest{}, helper)

	require.NoError(s.T(), err)
	assert.Equal(s.T(), 1, helper.createEvidenceCalls)
}

func (s *DependabotPluginSuite) TestEvalForBundle_CreateEvidenceError() {
	plugin := s.newPlugin(OperationalModeBundled)
	wantErr := errors.New("api unavailable")
	helper := &mockApiHelper{createEvidenceErr: wantErr}

	err := plugin.evalForBundle(context.Background(), s.newRepo(), nil, nil, &proto.EvalRequest{}, helper)

	require.ErrorIs(s.T(), err, wantErr)
}

func (s *DependabotPluginSuite) TestBuildGranularPolicyLabels_UsesGHSAFallbackAndMapsMediumToModerate() {
	repo := s.newRepo()
	policyContext := newGranularPolicyContext(repo)
	score := 7.23
	alert := s.newDetailedAlert("", "GHSA-123", "medium", "openssl", "gomod", &score)

	labels := buildGranularPolicyLabels(policyContext.labelsBase, alert)

	assert.Equal(s.T(), "GHSA-123", labels["cve_id"])
	assert.Equal(s.T(), "moderate", labels["impact"])
	assert.Equal(s.T(), "7.2", labels["cvss_score"])
	assert.Equal(s.T(), "test-repo", labels["repository"])
	assert.Equal(s.T(), "test-org", labels["organization"])
}

func (s *DependabotPluginSuite) TestBuildGranularPolicyLabels_UsesCVEDefaultsAndGitHubBranding() {
	repo := s.newRepo()
	policyContext := newGranularPolicyContext(repo)
	alert := s.newDetailedAlert("CVE-2026-0001", "GHSA-ignored", "critical", "lodash", "npm", nil)

	labels := buildGranularPolicyLabels(policyContext.labelsBase, alert)

	assert.Equal(s.T(), "CVE-2026-0001", labels["cve_id"])
	assert.Equal(s.T(), "critical", labels["impact"])
	assert.Equal(s.T(), "0.0", labels["cvss_score"])
	require.Len(s.T(), policyContext.inventory, 1)
	assert.Equal(s.T(), "GitHub Repository [test-repo]", policyContext.inventory[0].GetTitle())
}

func (s *DependabotPluginSuite) TestGranularPolicyInput_WrapsAlertInSingleElementSlice() {
	alert := s.newDetailedAlert("CVE-2026-0002", "GHSA-456", "high", "requests", "pip", nil)

	input := granularPolicyInput(alert)

	require.Len(s.T(), input, 1)
	assert.Same(s.T(), alert, input[0])
}

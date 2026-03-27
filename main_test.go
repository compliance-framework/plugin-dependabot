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

// --- evalForGranular ---

func (s *DependabotPluginSuite) TestEvalForGranular_NoAlerts() {
	plugin := s.newPlugin(OperationalModeGranular)
	helper := &mockApiHelper{}

	err := plugin.evalForGranular(context.Background(), s.newRepo(), nil, &proto.EvalRequest{}, helper)

	require.NoError(s.T(), err)
	assert.Equal(s.T(), 0, helper.createEvidenceCalls)
}

func (s *DependabotPluginSuite) TestEvalForGranular_CallsCreateEvidencePerAlert() {
	plugin := s.newPlugin(OperationalModeGranular)
	helper := &mockApiHelper{}
	alerts := []*github.DependabotAlert{s.newAlert(), s.newAlert(), s.newAlert()}

	// no policy paths → EvaluateGranularPolicies returns empty evidence without invoking OPA
	err := plugin.evalForGranular(context.Background(), s.newRepo(), alerts, &proto.EvalRequest{}, helper)

	require.NoError(s.T(), err)
	assert.Equal(s.T(), len(alerts), helper.createEvidenceCalls)
}

func (s *DependabotPluginSuite) TestEvalForGranular_CreateEvidenceError() {
	plugin := s.newPlugin(OperationalModeGranular)
	wantErr := errors.New("api unavailable")
	helper := &mockApiHelper{createEvidenceErr: wantErr}

	err := plugin.evalForGranular(context.Background(), s.newRepo(), []*github.DependabotAlert{s.newAlert()}, &proto.EvalRequest{}, helper)

	require.ErrorIs(s.T(), err, wantErr)
}

func (s *DependabotPluginSuite) TestEvalForGranular_StopsOnFirstCreateEvidenceError() {
	plugin := s.newPlugin(OperationalModeGranular)
	helper := &mockApiHelper{createEvidenceErr: errors.New("fail")}
	alerts := []*github.DependabotAlert{s.newAlert(), s.newAlert(), s.newAlert()}

	_ = plugin.evalForGranular(context.Background(), s.newRepo(), alerts, &proto.EvalRequest{}, helper)

	assert.Equal(s.T(), 1, helper.createEvidenceCalls, "loop should stop after first error")
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

func TestDependabotPlugin_FetchRepositories(t *testing.T) {

}

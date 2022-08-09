package snyk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Client provides methods to interact with the Snyk API v1
//
// References:
// - https://snyk.io/api/v1/
// - https://snyk.docs.apiary.io/#reference/general
type Client struct {
	Token string

	http *http.Client
}

// NewClient helps create a new Client object.
func NewClient(options ...ClientOption) (*Client, error) {
	c := Client{http: http.DefaultClient}

	for _, option := range options {
		err := option(&c)
		if err != nil {
			return nil, err
		}
	}

	if c.Token == "" {
		return nil, errors.New("token not set on client")
	}

	return &c, nil
}

// ClientOption is a function that accepts a Client, performs some
// sort of action/check on it, and returns an error.
type ClientOption = func(*Client) error

// WithTokenFromEnv allows an API token to be passed to the client using an environment variable.
func WithTokenFromEnv(varName string) ClientOption {
	return func(c *Client) error {
		val, ok := os.LookupEnv(varName)
		if !ok {
			return fmt.Errorf("%s is not set", varName)
		}
		c.Token = val
		return nil
	}
}

// WithToken allows an API token to be passed to the client directly.
func WithToken(token string) ClientOption {
	return func(c *Client) error {
		c.Token = token
		return nil
	}
}

// WithHTTPClient allows a user to user their own customized HTTP client. The default is the
// http package's DefaultHTTPClient which might not be ideal in many situations.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) error {
		c.http = hc
		return nil
	}
}

type apiError struct {
	Error       bool   `json:"error"`
	Message     string `json:"message"`
	CliMessage  string `json:"cliMessage"`
	UserMessage string `json:"userMessage"`
}

// RawQuery performs a general query against the API
func (c *Client) RawQuery(ctx context.Context, verb, path string, customHeaders map[string]string, body io.Reader, value interface{}) error {
	req, err := http.NewRequest(verb, fmt.Sprintf("https://snyk.io/api/v1/%s", path), body)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)

	req.Header.Add("Authorization", fmt.Sprintf("token %s", c.Token))
	req.Header.Add("Content-Type", "application/json; charset=utf-8")

	for k, v := range customHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if req.Method == "POST" && resp.StatusCode == http.StatusCreated {
		value = resp.Header.Get("Location")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		errorMesg := apiError{}

		err = json.NewDecoder(resp.Body).Decode(&errorMesg)
		if err != nil {
			return fmt.Errorf("unable to parse JSON after resp %s: %w", resp.Status, err)
		}

		// if the api error is empty, use the http status string which
		// contains some relevant information
		if errorMesg.Message == "" {
			return fmt.Errorf("http server status: %s", resp.Status)
		}

		return fmt.Errorf("%s", errorMesg.Message)
	}

	if value != nil {
		err = json.NewDecoder(resp.Body).Decode(value)
		if err != nil {
			return err
		}
	}

	return nil
}

// Organizations is a collection of organization information for the API token.
type Organization struct {
	Name  string `json:"name"`
	ID    string `json:"id"`
	Slug  string `json:"slug"`
	Url   string `json:"url"`
	Group struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	} `json:"group"`
}
type Organizations = []Organization

// Organizations gets an Organizations object.
func (c *Client) Organizations(ctx context.Context) (Organizations, error) {
	var wrapper struct {
		Organizations `json:"orgs"`
	}

	err := c.RawQuery(ctx, "GET", "orgs", nil, nil, &wrapper)
	if err != nil {
		return nil, err
	}

	return wrapper.Organizations, nil
}

// Members is a collection of member information for a group or organization.
type Members []struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Orgs     []struct {
		Name string `json:"name"`
		Role string `json:"role"`
	} `json:"orgs"`
	GroupRole string `json:"groupRole"`
}

// GroupMembers gets a GroupMembers object.
func (c *Client) GroupMembers(ctx context.Context, groupID string) (Members, error) {
	members := Members{}

	err := c.RawQuery(ctx, "GET", fmt.Sprintf("group/%s/members", groupID), nil, nil, &members)
	if err != nil {
		return nil, err
	}

	return members, nil
}

// CreateOrganization creates a new organization in the given group for which the
// token being used has admin access to.
func (c *Client) CreateOrganization(ctx context.Context, groupID string, newOrgName string) error {
	data := struct {
		Name string `json:"name"`
	}{
		newOrgName,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	body := bytes.NewReader(jsonBytes)

	return c.RawQuery(ctx, "POST", fmt.Sprintf("group/%s/org", groupID), nil, body, nil)
}

// OrganizationMembers gets a Members object for a given organization.
func (c *Client) OrganizationMembers(ctx context.Context, orgID string) (Members, error) {
	members := Members{}

	err := c.RawQuery(ctx, "GET", fmt.Sprintf("org/%s/members?includeGroupAdmins=true", orgID), nil, nil, &members)
	if err != nil {
		return nil, err
	}

	return members, nil
}

// UserInfo contains information about a user.
type UserInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// UserInfo gets a UserInfo object.
func (c *Client) UserInfo(ctx context.Context, userID string) (*UserInfo, error) {
	info := &UserInfo{}

	err := c.RawQuery(ctx, "GET", fmt.Sprintf("user/%s", userID), nil, nil, info)
	if err != nil {
		return nil, err
	}

	return info, nil
}

// InviteUserToOrganization will send an invite to a given user's email to join a given organization.
func (c *Client) InviteUserToOrganization(ctx context.Context, orgID string, email string) error {
	data := struct {
		Email string `json:"email"`
	}{
		email,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	body := bytes.NewReader(jsonBytes)

	return c.RawQuery(ctx, "POST", fmt.Sprintf("org/%s/invite", orgID), nil, body, nil)
}

// OrganizationNotificationSettings contains information about an organization's notification settings.
type OrganizationNotificationSettings struct {
	NewIssuesRemediations struct {
		Enabled       bool   `json:"enabled"`
		IssueSeverity string `json:"issueSeverity"`
		IssueType     string `json:"issueType"`
		Inherited     bool   `json:"inherited"`
	} `json:"new-issues-remediations"`
	ProjectImported struct {
		Enabled       bool   `json:"enabled"`
		IssueSeverity string `json:"issueSeverity"`
		IssueType     string `json:"issueType"`
		Inherited     bool   `json:"inherited"`
	} `json:"project-imported"`
	TestLimit struct {
		Enabled       bool   `json:"enabled"`
		IssueSeverity string `json:"issueSeverity"`
		IssueType     string `json:"issueType"`
		Inherited     bool   `json:"inherited"`
	} `json:"test-limit"`
	WeeklyReport struct {
		Enabled       bool   `json:"enabled"`
		IssueSeverity string `json:"issueSeverity"`
		IssueType     string `json:"issueType"`
		Inherited     bool   `json:"inherited"`
	} `json:"weekly-report"`
}

// OrganizationNotificationSettings will get a OrganizationNotificationSettings object.
func (c *Client) OrganizationNotificationSettings(ctx context.Context, orgID string) (*OrganizationNotificationSettings, error) {
	settings := &OrganizationNotificationSettings{}

	err := c.RawQuery(ctx, "GET", fmt.Sprintf("org/%s/notification-settings", orgID), nil, nil, settings)
	if err != nil {
		return nil, err
	}

	return settings, nil
}

// RemoveMemberFromOrganization will remove a member from an organization.
func (c *Client) RemoveMemberFromOrganization(ctx context.Context, orgID, userID string) error {
	return c.RawQuery(ctx, "PUT", fmt.Sprintf("org/%s/members/%s", orgID, userID), nil, nil, nil)
}

// UpdateMemberInOrganization will update a member in an organization.
func (c *Client) UpdateMemberInOrganization(ctx context.Context, orgID, userID, newRole string) error {
	data := struct {
		Role string `json:"role"`
	}{
		newRole,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	body := bytes.NewReader(jsonBytes)

	return c.RawQuery(ctx, "PUT", fmt.Sprintf("org/%s/members/%s", orgID, userID), nil, body, nil)
}

// Integrations contains a list of intergration information for an organization.
type Integrations = map[string]string

// OrganizationIntegrations gets a Integrations object.
func (c *Client) OrganizationIntegrations(ctx context.Context, orgID string) (Integrations, error) {
	integrations := Integrations{}

	err := c.RawQuery(ctx, "GET", fmt.Sprintf("org/%s/integrations", orgID), nil, nil, &integrations)
	if err != nil {
		return nil, err
	}

	return integrations, nil
}

// Project is an object which is a package that is actively
// tracked by Snyk.
type Project struct {
	Name                  string    `json:"name"`
	ID                    string    `json:"id"`
	Created               time.Time `json:"created"`
	Origin                string    `json:"origin"`
	Type                  string    `json:"type"`
	ReadOnly              bool      `json:"readOnly"`
	TestFrequency         string    `json:"testFrequency"`
	TotalDependencies     int       `json:"totalDependencies"`
	IssueCountsBySeverity struct {
		Low      int `json:"low"`
		High     int `json:"high"`
		Medium   int `json:"medium"`
		Critical int `json:"critical"`
	} `json:"issueCountsBySeverity"`
	LastTestedDate time.Time `json:"lastTestedDate"`
	ImportingUser  struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"importingUser"`
	ImageID        string `json:"imageId,omitempty"`
	ImageTag       string `json:"imageTag,omitempty"`
	ImageBaseImage string `json:"imageBaseImage,omitempty"`
	ImagePlatform  string `json:"imagePlatform,omitempty"`
	ImageCluster   string `json:"imageCluster,omitempty"`
	Owner          struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"owner"`
	BrowseUrl       string `json:"browseUrl,omitempty"`
	IsMonitored     bool   `json:"isMonitored"`
	Branch          string `json:"branch,omitempty"`
	TargetReference string `json:"targetReference,omitempty"`
	Tags            Tags   `json:"tags"`
}

// Projects is a collection of individual Project objects which is a package
// that is actively tracked by Snyk.
type Projects = []Project

// Tag is a key-value object that can be saved on a Project
type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Tags is a collection of Tag objects
type Tags []Tag

// ToMap returns the tags as a native map[string]string
func (tags Tags) ToMap() map[string]string {
	var data = map[string]string{}
	for _, tag := range tags {
		data[tag.Key] = tag.Value
	}

	return data
}

// OrganizationProjects gets a Projects object.
func (c *Client) OrganizationProjects(ctx context.Context, orgID string) (Projects, error) {
	var wrapper struct {
		Projects `json:"projects"`
	}

	err := c.RawQuery(ctx, "GET", fmt.Sprintf("org/%s/projects", orgID), nil, nil, &wrapper)
	if err != nil {
		return nil, err
	}

	return wrapper.Projects, nil
}

// OrganizationProject gets a Project object.
func (c *Client) OrganizationProject(ctx context.Context, orgID, projectID string) (*Project, error) {
	project := &Project{}

	err := c.RawQuery(ctx, "GET", fmt.Sprintf("org/%s/project/%s", orgID, projectID), nil, nil, project)
	if err != nil {
		return nil, err
	}

	return project, nil
}

// AddProjectTag adds a tag to a given project
func (c *Client) AddProjectTag(ctx context.Context, orgID, projectID, key, value string) (Tags, error) {
	var (
		tags struct {
			Tags Tags `json:"tags"`
		}
		data = Tag{
			Key:   key,
			Value: value,
		}
	)

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	body := bytes.NewReader(jsonBytes)

	err = c.RawQuery(ctx, "POST", fmt.Sprintf("org/%s/project/%s/tags", orgID, projectID), nil, body, &tags)

	return tags.Tags, err
}

// RemoveProjectTag removes a tag from a given project
func (c *Client) RemoveProjectTag(ctx context.Context, orgID, projectID, key, value string) (Tags, error) {
	var (
		tags struct {
			Tags Tags `json:"tags"`
		}
		data = Tag{
			Key:   key,
			Value: value,
		}
	)

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	body := bytes.NewReader(jsonBytes)

	err = c.RawQuery(ctx, "POST", fmt.Sprintf("org/%s/project/%s/tags/remove", orgID, projectID), nil, body, &tags)

	return tags.Tags, err
}

// Vulnerabilities are  from a given project's Issues.
type Vulnerabilities []struct {
	ID             string   `json:"id"`
	URL            string   `json:"url"`
	Title          string   `json:"title"`
	Type           string   `json:"type"`
	Description    string   `json:"description"`
	From           []string `json:"from"`
	Package        string   `json:"package"`
	Version        string   `json:"version"`
	Severity       string   `json:"severity"`
	Language       string   `json:"language"`
	PackageManager string   `json:"packageManager"`
	Semver         struct {
		Unaffected string `json:"unaffected"`
		//Vulnerable string `json:"vulnerable"`
	} `json:"semver"`
	PublicationTime time.Time `json:"publicationTime"`
	DisclosureTime  time.Time `json:"disclosureTime"`
	IsUpgradable    bool      `json:"isUpgradable"`
	IsPinnable      bool      `json:"isPinnable"`
	IsPatchable     bool      `json:"isPatchable"`
	Identifiers     struct {
		CVE         []interface{} `json:"CVE"`
		CWE         []interface{} `json:"CWE"`
		OSVDB       []interface{} `json:"OSVDB"`
		ALTERNATIVE []interface{} `json:"ALTERNATIVE"`
	} `json:"identifiers"`
	Credit    []string `json:"credit"`
	CVSSv3    string   `json:"CVSSv3"`
	CvssScore float64  `json:"cvssScore"`
	Patches   []struct {
		ID               string        `json:"id"`
		Urls             []string      `json:"urls"`
		Version          string        `json:"version"`
		Comments         []interface{} `json:"comments"`
		ModificationTime time.Time     `json:"modificationTime"`
	} `json:"patches"`
	IsIgnored   bool          `json:"isIgnored"`
	IsPatched   bool          `json:"isPatched"`
	UpgradePath []interface{} `json:"upgradePath"`
	Ignored     []struct {
		Reason  string    `json:"reason"`
		Expires time.Time `json:"expires"`
		Source  string    `json:"source"`
	} `json:"ignored,omitempty"`
	Patched []struct {
		Patched time.Time `json:"patched"`
	} `json:"patched,omitempty"`
}

type projectIssuesWrapper struct {
	Ok     bool `json:"ok"`
	Issues struct {
		Vulnerabilities Vulnerabilities `json:"vulnerabilities"`
		Licenses        []interface{}   `json:"licenses"`
	} `json:"issues"`
	DependencyCount int    `json:"dependencyCount"`
	PackageManager  string `json:"packageManager"`
}

type projectFilters struct {
	Severities []string `json:"severities"`
	Types      []string `json:"types"`
	Ignored    bool     `json:"ignored"`
	Patched    bool     `json:"patched"`
}

func defaultFilters() *projectFilters {
	return &projectFilters{
		Severities: []string{
			"high", "medium", "low",
		},
		Types: []string{
			"vuln", "license",
		},
		Ignored: false,
		Patched: false,
	}
}

func (c *Client) projectIssues(ctx context.Context, orgID, projectID string, filters *projectFilters) (*projectIssuesWrapper, error) {
	pIssues := &projectIssuesWrapper{}

	if filters == nil {
		filters = defaultFilters()
	}

	data := struct {
		Filters *projectFilters `json:"filters"`
	}{
		filters,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	body := bytes.NewReader(jsonBytes)

	err = c.RawQuery(ctx, "POST", fmt.Sprintf("org/%s/project/%s/issues", orgID, projectID), nil, body, pIssues)
	if err != nil {
		return nil, err
	}

	return pIssues, nil
}

// ProjectVulnerabilities gets vulnerabilities for a given project in a given organization.
func (c *Client) ProjectVulnerabilities(ctx context.Context, orgID, projectID string, filters *projectFilters) (Vulnerabilities, error) {
	issues, err := c.projectIssues(ctx, orgID, projectID, filters)
	if err != nil {
		return nil, err
	}
	return issues.Issues.Vulnerabilities, nil
}

// ProjectCVEs gets CVE strings for a given project in a given organization.
func (c *Client) ProjectCVEs(ctx context.Context, orgID, projectID string, filters *projectFilters) ([]string, error) {
	vulnerabilities, err := c.ProjectVulnerabilities(ctx, orgID, projectID, filters)
	if err != nil {
		return nil, err
	}

	set := make(map[string]bool)

	for _, vuln := range vulnerabilities {
		for _, cve := range vuln.Identifiers.CVE {
			cveStr := fmt.Sprintf("%v", cve)
			set[cveStr] = true
		}
	}

	cveStrs := []string{}

	for str := range set {
		cveStrs = append(cveStrs, str)
	}

	return cveStrs, nil
}

// RemoveOrganizationProject deletes a given project from the given organization.
func (c *Client) RemoveOrganizationProject(ctx context.Context, orgID, projectID string) error {
	return c.RawQuery(ctx, "DELETE", fmt.Sprintf("org/%s/project/%s", orgID, projectID), nil, nil, nil)
}

// OrganizationImportProjectOptions is used with the OrganizationImportProject function.
type OrganizationImportProjectOptions = map[string]interface{}

// FilesToImport is syntactic-sugar to DRY up the *Import function code.
type FilesToImport = []ImportFile

// ImportFile is used in FilesToImport
type ImportFile struct {
	Path string `json:"path"`
}

// ImportFiles is a helpful wrapper to take multiple file-path strings
// and turn them into a FilesToImport object.
func ImportFiles(paths ...string) FilesToImport {
	fti := FilesToImport{}

	for _, path := range paths {
		fti = append(fti, ImportFile{Path: path})
	}

	return fti
}

// GitHubImport returns a github-flavored OrganizationImportProjectOptions object.
func GitHubImport(owner, name, branch string, files FilesToImport) OrganizationImportProjectOptions {
	return OrganizationImportProjectOptions{
		"target": map[string]string{
			"owner":  owner,
			"name":   name,
			"branch": branch,
		},
		"files": files,
	}
}

// DockerHubImport returns a docker-flavored OrganizationImportProjectOptions object.
func DockerHubImport(organization, repository, tag string) OrganizationImportProjectOptions {
	return OrganizationImportProjectOptions{
		"target": map[string]string{
			"name": fmt.Sprintf("%s/%s:%s", organization, repository, tag),
		},
	}
}

// AWSLambdaImport returns a aws-lambda-flavored OrganizationImportProjectOptions object.
func AWSLambdaImport(functionID string, files FilesToImport) OrganizationImportProjectOptions {
	return OrganizationImportProjectOptions{
		"target": map[string]string{
			"functionId": functionID,
		},
		"files": files,
	}
}

// OrganizationImportProject helps import a project of various types to an organization.
func (c *Client) OrganizationImportProject(ctx context.Context, orgID, integrationID string, importOption OrganizationImportProjectOptions) (string, error) {
	jsonBytes, err := json.Marshal(importOption)
	if err != nil {
		return "", err
	}
	body := bytes.NewReader(jsonBytes)

	callBackURL := ""

	fmt.Println(string(jsonBytes))

	err = c.RawQuery(ctx, "POST", fmt.Sprintf("org/%s/integrations/%s/import", orgID, integrationID), nil, body, &callBackURL)
	if err != nil {
		return "", err
	}

	return callBackURL, nil
}

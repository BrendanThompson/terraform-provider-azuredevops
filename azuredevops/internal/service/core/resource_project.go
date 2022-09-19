package core

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/microsoft/azure-devops-go-api/azuredevops/v6/core"
	"github.com/microsoft/azure-devops-go-api/azuredevops/v6/featuremanagement"
	"github.com/microsoft/azure-devops-go-api/azuredevops/v6/git"
	"github.com/microsoft/azure-devops-go-api/azuredevops/v6/operations"
	"github.com/microsoft/terraform-provider-azuredevops/azuredevops/internal/client"
	"github.com/microsoft/terraform-provider-azuredevops/azuredevops/internal/utils"
	"github.com/microsoft/terraform-provider-azuredevops/azuredevops/internal/utils/converter"
	"github.com/microsoft/terraform-provider-azuredevops/azuredevops/internal/utils/suppress"
)

// timeout used to wait for operations on projects to finish before executing an update or delete
var projectBusyTimeoutDuration time.Duration = 6
var projectRetryTimeoutDuration time.Duration = 3

// RepoInitType strategy for initializing the repo
type RepoInitType string

type repoInitTypeValuesType struct {
	Uninitialized RepoInitType
	Clean         RepoInitType
	Fork          RepoInitType
	Import        RepoInitType
}

// RepoInitTypeValues enum of strategy for initializing the repo
var RepoInitTypeValues = repoInitTypeValuesType{
	Uninitialized: "Uninitialized",
	Clean:         "Clean",
	Fork:          "Fork",
	Import:        "Import",
}

// ResourceProject schema and implementation for project resource
func ResourceProject() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceProjectCreate,
		ReadContext:   resourceProjectRead,
		UpdateContext: resourceProjectUpdate,
		DeleteContext: resourceProjectDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(10 * time.Minute),
			Read:   schema.DefaultTimeout(5 * time.Minute),
			Update: schema.DefaultTimeout(10 * time.Minute),
			Delete: schema.DefaultTimeout(10 * time.Minute),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:             schema.TypeString,
				Required:         true,
				ValidateFunc:     validation.StringIsNotWhiteSpace,
				DiffSuppressFunc: suppress.CaseDifference,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "",
			},
			"visibility": {
				Type:             schema.TypeString,
				Optional:         true,
				Default:          core.ProjectVisibilityValues.Private,
				DiffSuppressFunc: suppress.CaseDifference,
				ValidateFunc: validation.StringInSlice([]string{
					string(core.ProjectVisibilityValues.Private),
					string(core.ProjectVisibilityValues.Public),
				}, false),
			},
			"version_control": {
				Type:             schema.TypeString,
				ForceNew:         true,
				Optional:         true,
				Default:          core.SourceControlTypesValues.Git,
				DiffSuppressFunc: suppress.CaseDifference,
				ValidateFunc: validation.StringInSlice([]string{
					string(core.SourceControlTypesValues.Git),
					string(core.SourceControlTypesValues.Tfvc),
				}, true),
			},
			"work_item_template": {
				Type:             schema.TypeString,
				ForceNew:         true,
				Optional:         true,
				ValidateFunc:     validation.StringIsNotWhiteSpace,
				DiffSuppressFunc: suppress.CaseDifference,
				Default:          "Agile",
			},
			"process_template_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"features": {
				Type:         schema.TypeMap,
				Optional:     true,
				ValidateFunc: validateProjectFeatures,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"initialization": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				MinItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"init_type": {
							Type:     schema.TypeString,
							Required: true,
							ForceNew: true,
							ValidateFunc: validation.StringInSlice([]string{
								string(RepoInitTypeValues.Clean),
								string(RepoInitTypeValues.Fork),
								string(RepoInitTypeValues.Import),
								string(RepoInitTypeValues.Uninitialized),
							}, false),
						},
						"source_type": {
							Type:         schema.TypeString,
							Optional:     true,
							ForceNew:     true,
							ValidateFunc: validation.StringInSlice([]string{"Git"}, false),
							RequiredWith: []string{"initialization.0.source_url"},
						},
						"source_url": {
							Type:         schema.TypeString,
							Optional:     true,
							ForceNew:     true,
							Default:      "",
							RequiredWith: []string{"initialization.0.source_type"},
							ValidateFunc: validation.IsURLWithHTTPorHTTPS,
						},
						"service_connection_id": {
							Type:     schema.TypeString,
							Optional: true,
							RequiredWith: []string{
								"initialization.0.source_url",
								"initialization.0.source_type",
							},
							Default: "",
						},
						"default_branch": {
							Type: schema.TypeString,
							Optional: true,
							Default: "main",
						},
					},
				},
			},
		},
	}
}

// A helper type that is used for transient info only used during repo creation
type repoInitializationMeta struct {
	initType            string
	sourceType          string
	sourceURL           string
	serviceConnectionID string
	defaultBranch string
}

func resourceProjectCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	clients := m.(*client.AggregatedClient)
	project, initialization, err := expandProject(clients, d, true)
	if err != nil {
		return diag.FromErr(fmt.Errorf("Error converting terraform data model to Azure DevOps project reference: %+v", err))
	}

	err = createProject(clients, project, d.Timeout(schema.TimeoutCreate))
	if err != nil {
		return diag.FromErr(fmt.Errorf(" creating project: %v", err))
	}

	featureStates, ok := d.GetOk("features")
	if ok {
		err = configureProjectFeatures(clients, "", *project.Name, &featureStates, d.Timeout(schema.TimeoutDelete))
		if err != nil {
			return diag.FromErr(err)
		}
	}

	repo, err := getDefaultRepository(clients, project.Name)
	if err != nil {
		return diag.FromErr(err)
	}

	if initialization != nil && strings.EqualFold(initialization.initType, string(RepoInitTypeValues.Import)) &&
		strings.EqualFold(initialization.sourceType, "Git") {
		importRequest := git.GitImportRequest{
			Parameters: &git.GitImportRequestParameters{
				GitSource: &git.GitImportGitSource{
					Url: &initialization.sourceURL,
				},
			},
			Repository: repo,
		}

		if initialization.serviceConnectionID != "" {
			importRequest.Parameters.ServiceEndpointId = converter.UUID(initialization.serviceConnectionID)
			importRequest.Parameters.DeleteServiceEndpointAfterImportIsDone = converter.Bool(false)
		}

		_, importErr := createImportRequest(clients, importRequest, *project.Name, *repo.Name)
		if importErr != nil {
			return diag.FromErr(fmt.Errorf("Error import repository in Azure DevOps: %+v ", importErr))
		}
	}

	if initialization != nil && strings.EqualFold(initialization.initType, string(RepoInitTypeValues.Clean)) {
		err = initializeGitRepository(clients, repo, converter.String(fmt.Sprintf("refs/heads/%s", initialization.defaultBranch)))
		if err != nil {
			return diag.FromErr(fmt.Errorf("Error initializing repository in Azure DevOps: %+v", err))
		}
	}

	if initialization != nil && !(strings.EqualFold(initialization.initType, string(RepoInitTypeValues.Uninitialized))) {
		err := waitForBranch(clients, project.Name)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	d.Set("name", *project.Name)
	return resourceProjectRead(ctx, d, m)
}

// Make API call to create the project and wait for an async success/fail response from the service
func createProject(clients *client.AggregatedClient, project *core.TeamProject, timeoutSeconds time.Duration) error {
	operationRef, err := clients.CoreClient.QueueCreateProject(clients.Ctx, core.QueueCreateProjectArgs{ProjectToCreate: project})
	if err != nil {
		return err
	}

	stateConf := &resource.StateChangeConf{
		ContinuousTargetOccurence: 1,
		Delay:                     5 * time.Second,
		MinTimeout:                10 * time.Second,
		Pending: []string{
			string(operations.OperationStatusValues.InProgress),
			string(operations.OperationStatusValues.Queued),
			string(operations.OperationStatusValues.NotSet),
		},
		Target: []string{
			string(operations.OperationStatusValues.Failed),
			string(operations.OperationStatusValues.Succeeded),
			string(operations.OperationStatusValues.Cancelled)},
		Refresh: projectStatusRefreshFunc(clients, operationRef),
		Timeout: timeoutSeconds,
	}

	if _, err := stateConf.WaitForStateContext(clients.Ctx); err != nil {
		return fmt.Errorf(" waiting for project ready. %v ", err)
	}

	return nil
}

func getDefaultRepository(clients *client.AggregatedClient, project *string) (*git.GitRepository, error) {
	args := git.GetRepositoryArgs{
		RepositoryId: project,
		Project:      project,
	}

	gitRepo, err := clients.GitReposClient.GetRepository(clients.Ctx, args)
	if err != nil {
		return nil, err
	}

	return gitRepo, nil
}

func waitForBranch(clients *client.AggregatedClient, projectName *string) error {
	stateConf := &resource.StateChangeConf{
		Pending: []string{"Waiting"},
		Target:  []string{"Synched"},
		Refresh: func() (interface{}, string, error) {
			state := "Waiting"
			gitRepo, err := getDefaultRepository(clients, projectName)
			if err != nil {
				return nil, "", fmt.Errorf("Error reading repository: %+v", err)
			}

			if converter.ToString(gitRepo.DefaultBranch, "") != "" {
				state = "Synched"
			}

			return state, state, nil
		},
		Timeout:                   60 * time.Second,
		MinTimeout:                2 * time.Second,
		Delay:                     1 * time.Second,
		ContinuousTargetOccurence: 1,
	}
	if _, err := stateConf.WaitForState(); err != nil { //nolint:staticcheck
		return fmt.Errorf("Error retrieving expected branch for repository [%s]: %+v", *projectName, err)
	}
	return nil
}

func createImportRequest(clients *client.AggregatedClient, gitImportRequest git.GitImportRequest, project string, repositoryID string) (*git.GitImportRequest, error) {
	args := git.CreateImportRequestArgs{
		ImportRequest: &gitImportRequest,
		Project:       &project,
		RepositoryId:  &repositoryID,
	}

	return clients.GitReposClient.CreateImportRequest(clients.Ctx, args)
}

func initializeGitRepository(clients *client.AggregatedClient, repo *git.GitRepository, defaultBranch *string) error {
	branchName := converter.ToString(defaultBranch, "")
	if strings.EqualFold(branchName, "") {
		branchName = "refs/heads/main"
	}
	args := git.CreatePushArgs{
		RepositoryId: repo.Name,
		Project:      repo.Project.Name,
		Push: &git.GitPush{
			RefUpdates: &[]git.GitRefUpdate{
				{
					Name:        converter.String(branchName),
					OldObjectId: converter.String("0000000000000000000000000000000000000000"),
				},
			},
			Commits: &[]git.GitCommitRef{
				{
					Comment: converter.String("Initial commit."),
					Changes: &[]interface{}{
						git.Change{
							ChangeType: &git.VersionControlChangeTypeValues.Add,
							Item: git.GitItem{
								Path: converter.String("/readme.md"),
							},
							NewContent: &git.ItemContent{
								ContentType: &git.ItemContentTypeValues.RawText,
								Content:     repo.Project.Name,
							},
						},
					},
				},
			},
		},
	}

	_, err := clients.GitReposClient.CreatePush(clients.Ctx, args)

	return err
}

// Configure projects features for a project. If projectID is "" then the projectName will be used to locate (read) the project
func configureProjectFeatures(clients *client.AggregatedClient, projectID string, projectName string, featureStates *interface{}, timeout time.Duration) error {
	if featureStates == nil {
		return nil
	}
	featureStateMap := (*featureStates).(map[string]interface{})
	project, err := projectRead(clients, projectID, projectName)
	if err != nil {
		return err
	}
	projectID = project.Id.String()
	err = updateProjectFeatureStates(clients.Ctx, clients.FeatureManagementClient, projectID, &featureStateMap)
	if err != nil {
		ierr := deleteProject(clients, projectID, timeout)
		if ierr != nil {
			err = fmt.Errorf("failed to delete new project %v after failed to apply feature settings; %w", ierr, err)
		}
		return err
	}
	return nil
}

func projectStatusRefreshFunc(clients *client.AggregatedClient, operationRef *operations.OperationReference) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		ret, err := clients.OperationsClient.GetOperation(clients.Ctx, operations.GetOperationArgs{
			OperationId: operationRef.Id,
			PluginId:    operationRef.PluginId,
		})
		if err != nil {
			return nil, string(operations.OperationStatusValues.Failed), err
		}

		if *ret.Status != operations.OperationStatusValues.Succeeded {
			log.Printf("[DEBUG] Waiting for project operation success. Operation result %v", ret.DetailedMessage)
		}

		return ret, string(*ret.Status), nil
	}
}

func resourceProjectRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	clients := m.(*client.AggregatedClient)
	id := d.Id()
	name := d.Get("name").(string)

	project, err := projectRead(clients, id, name)
	if err != nil {
		if utils.ResponseWasNotFound(err) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(fmt.Errorf(" looking up project with (ID: %s or Name: %s). Error: %+v", id, name, err))
	}

	err = flattenProject(clients, d, project)
	if err != nil {
		return diag.FromErr(fmt.Errorf(" flattening project: %v", err))
	}
	return nil
}

func projectRead(clients *client.AggregatedClient, projectID string, projectName string) (*core.TeamProject, error) {
	identifier := projectID
	if identifier == "" {
		identifier = projectName
	}

	var project *core.TeamProject
	var err error

	//keep retrying until timeout to handle service inconsistent response
	//lint:ignore SA1019
	err = resource.Retry(projectRetryTimeoutDuration*time.Minute, func() *resource.RetryError { //nolint:staticcheck
		project, err = clients.CoreClient.GetProject(clients.Ctx, core.GetProjectArgs{
			ProjectId:           &identifier,
			IncludeCapabilities: converter.Bool(true),
			IncludeHistory:      converter.Bool(false),
		})
		if err != nil {
			if utils.ResponseWasNotFound(err) {
				return resource.NonRetryableError(err)
			}
			return resource.RetryableError(err)
		}
		return nil
	})

	if err != nil {
		if utils.ResponseWasNotFound(err) {
			return nil, err
		}
		return nil, fmt.Errorf(" Project not found. (ID: %s or name: %s), Error: %+v", projectID, projectName, err)
	}
	return project, nil
}

func resourceProjectUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	clients := m.(*client.AggregatedClient)
	project, _, err := expandProject(clients, d, false)
	if err != nil {
		return diag.FromErr(fmt.Errorf(" converting terraform data model to AzDO project reference: %+v", err))
	}

	requiresUpdate := false
	if !d.HasChange("name") {
		project.Name = nil
	} else {
		requiresUpdate = true
	}
	if !d.HasChange("description") {
		project.Description = nil
	} else {
		requiresUpdate = true
	}
	if !d.HasChange("visibility") {
		project.Visibility = nil
	} else {
		requiresUpdate = true
	}

	if requiresUpdate {
		log.Printf("[TRACE] resourceProjectUpdate: updating project")
		err = updateProject(clients, project, d.Timeout(schema.TimeoutUpdate))
		if err != nil {
			return diag.FromErr(fmt.Errorf("Error updating project: %v", err))
		}
	}

	if d.HasChange("features") {
		log.Printf("[TRACE] resourceProjectUpdate: updating project features")

		var featureStates map[string]interface{}
		oldFeatureStates, newFeatureStates := d.GetChange("features")
		if len(newFeatureStates.(map[string]interface{})) <= 0 {
			log.Printf("[TRACE] resourceProjectUpdate: new feature definition is empty; resetting to defaults")

			featureStates = oldFeatureStates.(map[string]interface{})
			pfeatureStates, err := getDefaultProjectFeatureStates(&featureStates)
			if err != nil {
				return nil
			}
			featureStates = *pfeatureStates
		} else {
			featureStates = newFeatureStates.(map[string]interface{})
		}

		err := updateProjectFeatureStates(clients.Ctx, clients.FeatureManagementClient, project.Id.String(), &featureStates)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	return resourceProjectRead(ctx, d, m)
}

func updateProject(clients *client.AggregatedClient, project *core.TeamProject, timeoutSeconds time.Duration) error {
	var operationRef *operations.OperationReference

	// project updates may fail if there is activity going on in the project. A retry can be employed
	// to gracefully handle errors encountered for updates, up until a timeout is reached
	err := resource.RetryContext(clients.Ctx, projectBusyTimeoutDuration*time.Minute, func() *resource.RetryError {
		var updateErr error
		operationRef, updateErr = clients.CoreClient.UpdateProject(
			clients.Ctx,
			core.UpdateProjectArgs{
				ProjectUpdate: project,
				ProjectId:     project.Id,
			})
		if updateErr != nil {
			return resource.RetryableError(updateErr)
		}
		return nil
	})

	if err != nil {
		return err
	}

	stateConf := &resource.StateChangeConf{
		ContinuousTargetOccurence: 1,
		Delay:                     10 * time.Second,
		MinTimeout:                10 * time.Second,
		Pending: []string{
			string(operations.OperationStatusValues.InProgress),
			string(operations.OperationStatusValues.Queued),
			string(operations.OperationStatusValues.NotSet),
		},
		Target: []string{
			string(operations.OperationStatusValues.Failed),
			string(operations.OperationStatusValues.Succeeded),
			string(operations.OperationStatusValues.Cancelled)},
		Refresh: projectStatusRefreshFunc(clients, operationRef),
		Timeout: timeoutSeconds,
	}

	if _, err := stateConf.WaitForStateContext(clients.Ctx); err != nil {
		return fmt.Errorf(" waiting for project ready. %v ", err)
	}
	return nil
}

func resourceProjectDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	clients := m.(*client.AggregatedClient)
	id := d.Id()

	err := deleteProject(clients, id, d.Timeout(schema.TimeoutDelete))
	if err != nil {
		return diag.FromErr(fmt.Errorf(" deleting project: %v", err))
	}

	return nil
}

func deleteProject(clients *client.AggregatedClient, id string, timeoutSeconds time.Duration) error {
	uuid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf(" Invalid project UUID: %s", id)
	}

	var operationRef *operations.OperationReference

	// project deletes may fail if there is activity going on in the project. A retry can be employed
	// to gracefully handle errors encountered for deletes, up until a timeout is reached
	err = resource.RetryContext(clients.Ctx, projectBusyTimeoutDuration*time.Minute, func() *resource.RetryError {
		var deleteErr error
		operationRef, deleteErr = clients.CoreClient.QueueDeleteProject(clients.Ctx, core.QueueDeleteProjectArgs{
			ProjectId: &uuid,
		})

		if deleteErr != nil {
			return resource.RetryableError(deleteErr)
		}
		return nil
	})

	if err != nil {
		return err
	}

	stateConf := &resource.StateChangeConf{
		ContinuousTargetOccurence: 1,
		Delay:                     10 * time.Second,
		MinTimeout:                10 * time.Second,
		Pending: []string{
			string(operations.OperationStatusValues.InProgress),
			string(operations.OperationStatusValues.Queued),
			string(operations.OperationStatusValues.NotSet),
		},
		Target: []string{
			string(operations.OperationStatusValues.Failed),
			string(operations.OperationStatusValues.Succeeded),
			string(operations.OperationStatusValues.Cancelled)},
		Refresh: projectStatusRefreshFunc(clients, operationRef),
		Timeout: timeoutSeconds,
	}

	if _, err := stateConf.WaitForStateContext(clients.Ctx); err != nil {
		return fmt.Errorf(" waiting for project ready. %v ", err)
	}
	return nil
}

// Convert internal Terraform data structure to an AzDO data structure
func expandProject(clients *client.AggregatedClient, d *schema.ResourceData, forCreate bool) (*core.TeamProject, *repoInitializationMeta, error) {
	workItemTemplate := d.Get("work_item_template").(string)
	processTemplateID, err := lookupProcessTemplateID(clients, workItemTemplate)
	if err != nil {
		return nil, nil, err
	}

	// an "error" is OK here as it is expected in the case that the ID is not set in the resource data
	var projectID *uuid.UUID
	parsedID, err := uuid.Parse(d.Id())
	if err == nil {
		projectID = &parsedID
	}

	visibility := core.ProjectVisibility(d.Get("visibility").(string))

	var capabilities *map[string]map[string]string
	if forCreate {
		capabilities = &map[string]map[string]string{
			"versioncontrol": {
				"sourceControlType": d.Get("version_control").(string),
			},
			"processTemplate": {
				"templateTypeId": processTemplateID,
			},
		}
	}

	project := &core.TeamProject{
		Id:           projectID,
		Name:         converter.String(d.Get("name").(string)),
		Description:  converter.String(d.Get("description").(string)),
		Visibility:   &visibility,
		Capabilities: capabilities,
	}

	var initialization *repoInitializationMeta = nil
	initData := d.Get("initialization").([]interface{})
	// Note: If configured, this will be of length 1 based on the schema definition above.
	if len(initData) == 1 {
		initValues := initData[0].(map[string]interface{})

		initialization = &repoInitializationMeta{
			initType:            initValues["init_type"].(string),
			sourceType:          initValues["source_type"].(string),
			sourceURL:           initValues["source_url"].(string),
			serviceConnectionID: initValues["service_connection_id"].(string),
			defaultBranch: initValues["default_branch"].(string),
		}

		if strings.EqualFold(initialization.initType, "clean") {
			initialization.sourceType = ""
			initialization.sourceURL = ""
			initialization.serviceConnectionID = ""
		}
	} else if len(initData) > 1 {
		return nil, nil, fmt.Errorf("Multiple initialization blocks")
	}

	return project, initialization, nil
}

func flattenProject(clients *client.AggregatedClient, d *schema.ResourceData, project *core.TeamProject) error {
	processTemplateID := (*project.Capabilities)["processTemplate"]["templateTypeId"]
	processTemplateName, err := lookupProcessTemplateName(clients, processTemplateID)

	if err != nil {
		return err
	}

	var currentFeatureStates *map[ProjectFeatureType]featuremanagement.ContributedFeatureEnabledValue
	features, ok := d.GetOk("features")
	if ok {
		featureStates := features.(map[string]interface{})
		states, err := getConfiguredProjectFeatureStates(clients.Ctx, clients.FeatureManagementClient, &featureStates, project.Id.String())
		if err != nil {
			return nil
		}
		currentFeatureStates = states
	}

	d.SetId(project.Id.String())
	d.Set("name", project.Name)
	d.Set("visibility", project.Visibility)
	d.Set("description", project.Description)
	d.Set("version_control", (*project.Capabilities)["versioncontrol"]["sourceControlType"])
	d.Set("process_template_id", processTemplateID)
	d.Set("work_item_template", processTemplateName)
	d.Set("features", currentFeatureStates)

	return nil
}

// given a process template name, get the process template ID
func lookupProcessTemplateID(clients *client.AggregatedClient, templateName string) (string, error) {
	processes, err := clients.CoreClient.GetProcesses(clients.Ctx, core.GetProcessesArgs{})
	if err != nil {
		return "", err
	}

	for _, p := range *processes {
		// Process names are case insensitive
		if strings.EqualFold(*p.Name, templateName) {
			return p.Id.String(), nil
		}
	}

	return "", fmt.Errorf("No process template found")
}

// given a process template ID, get the process template name
func lookupProcessTemplateName(clients *client.AggregatedClient, templateID string) (string, error) {
	id, err := uuid.Parse(templateID)
	if err != nil {
		return "", fmt.Errorf("Error parsing Work Item Template ID, got %s: %v", templateID, err)
	}

	process, err := clients.CoreClient.GetProcessById(clients.Ctx, core.GetProcessByIdArgs{
		ProcessId: &id,
	})

	if err != nil {
		return "", fmt.Errorf("Error looking up template by ID: %v", err)
	}

	return *process.Name, nil
}

---
layout: "azuredevops"
page_title: "AzureDevops: azuredevops_project"
description: |-
  Manages a project within Azure DevOps organization.
---

# azuredevops_project

Manages a project within Azure DevOps.

## Example Usage

```hcl
resource "azuredevops_project" "example" {
  name               = "Example Project"
  visibility         = "private"
  version_control    = "Git"
  work_item_template = "Agile"
  description        = "Managed by Terraform"
  features = {
    "testplans" = "disabled"
    "artifacts" = "disabled"
  }
}
```

## Argument Reference

The following arguments are supported:

- `name` - (Required) The Project Name.
- `description` - (Optional) The Description of the Project.
- `visibility` - (Optional) Specifies the visibility of the Project. Valid values: `private` or `public`. Defaults to `private`.
- `version_control` - (Optional) Specifies the version control system. Valid values: `Git` or `Tfvc`. Defaults to `Git`.
- `work_item_template` - (Optional) Specifies the work item template. Valid values: `Agile`, `Basic`, `CMMI` or `Scrum`. Defaults to `Agile`.
- `features` - (Optional) Defines the status (`enabled`, `disabled`) of the project features.  
   Valid features are `boards`, `repositories`, `pipelines`, `testplans`, `artifacts`
- `initialization` - (Optional) An `initialization` block as documented below.

`initialization` - (Optional) block supports the following:

- `init_type` - (Required) The type of repository to create. Valid values: `Uninitialized`, `Clean` or `Import`.
- `source_type` - (Optional) Type of the source repository. Used if the `init_type` is `Import`. Valid values: `Git`.
- `source_url` - (Optional) The URL of the source repository. Used if the `init_type` is `Import`.
- `service_connection_id` (Optional) The id of service connection used to authenticate to a private repository for import initialization.
- `branch_name` (Optional) The branch name to use when the default repository is initialised. 


> **NOTE:**  
> It's possible to define project features both within the [`azuredevops_project_features` resource](project_features.html) and
> via the `features` block by using the [`azuredevops_project` resource](project.html).
> However it's not possible to use both methods to manage features, since there'll be conflicts.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

- `id` - The Project ID of the Project.
- `process_template_id` - The Process Template ID used by the Project.

## Relevant Links

- [Azure DevOps Service REST API 6.0 - Projects](https://docs.microsoft.com/en-us/rest/api/azure/devops/core/projects?view=azure-devops-rest-6.0)

## Import

Azure DevOps Projects can be imported using the project name or by the project Guid, e.g.

```sh
terraform import azuredevops_project.example "Example Project"
```

or

```sh
terraform import azuredevops_project.example 00000000-0000-0000-0000-000000000000
```

## PAT Permissions Required

- **Project & Team**: Read, Write, & Manage

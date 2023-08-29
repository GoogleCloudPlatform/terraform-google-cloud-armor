# Cloud Armor Policy with preconfigured rules, custom rules and security rules

This example configures a single cloud armor policy with following types of rules:
- Pre-configured rules
- Custom rules
- Security rules

## Usage

To run this example you need to execute:

```bash
export TF_VAR_project_id="your_project_id"
```

```bash
terraform init
terraform plan
terraform apply
```

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| project\_id | The project in which the resource belongs | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| policy\_name | Security Policy name |
| project\_id | The project ID |
| security\_policy | Cloud Armor security policy created |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

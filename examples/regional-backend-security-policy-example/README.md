# Regional Cloud Armor Policy with preconfigured rules, custom rules and security rules

This example configures a regional cloud armor policy with following types of rules:
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
| region | Name of Regional Network Security policy created |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

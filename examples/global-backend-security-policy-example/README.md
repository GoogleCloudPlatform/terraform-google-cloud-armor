# Simple Cloud Armor Policy with pre-configured rules, custom rules and security rules

This example configures a single cloud armor policy with following types of rules:
- Pre-configured rules
- Custom rules
- Security rules
- Threat Intelligence Rules (Requires [Cloud Armor Enterprise](https://cloud.google.com/armor/docs/armor-enterprise-overview). Remove these rules if you dont have Cloud Armor Enterprise enabled for your project)
- Rule for Automatically deploying Adaptive Protection suggested rules (Requires [Cloud Armor Enterprise](https://cloud.google.com/armor/docs/armor-enterprise-overview). Remove these rules if you dont have Cloud Armor Enterprise enabled for your project)

This example also shows how you can deploy custom rules with [address groups](https://cloud.google.com/armor/docs/address-groups-using)

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
| address\_group\_name | n/a |
| policy\_name | Security Policy name |
| security\_policy | Cloud Armor security policy created |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

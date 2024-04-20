# Enable Cloud Armor Network Edge Security Policy

This example creates network edge security policy with policy rules. Feature is only availalable to projects enrolled in [Cloud Armor Enterprise](https://cloud.google.com/armor/docs/armor-enterprise-overview) with [Advanced network DDoS protection](https://cloud.google.com/armor/docs/advanced-network-ddos#activate-advanced-ddos-protection) enabled. You can use [example](../advanced-network-ddos-protection/) sub-module to deploy advanced newtork ddos protection.

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
| policy\_rules | Security policy rules created |
| security\_policy | Regional Network Security policy created |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

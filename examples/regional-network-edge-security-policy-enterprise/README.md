# Cloud Armor Network Edge Security Policy

This example creates [network edge security policy](https://cloud.google.com/armor/docs/network-edge-policies) with policy rules. Feature is only available to projects enrolled in [Cloud Armor Enterprise](https://cloud.google.com/armor/docs/armor-enterprise-overview) with [Advanced network DDoS protection](https://cloud.google.com/armor/docs/advanced-network-ddos#activate-advanced-ddos-protection) enabled. You can use [this sub-module](../advanced-network-ddos-protection/) to enable `advanced network ddos protection `. See [example](../regional-advanced-network-ddos-protection-enterprise/) for enabling advanced network ddos protection. If you need an end to end example for deploying security policy and attach it to backend service see [complete example](../regional-adv-ddos-and-edge-security-policy-complete/)

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
| network\_edge\_security\_policy\_no\_rules | Regional Network Security policy created |
| policy\_rules | Security policy rules created |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

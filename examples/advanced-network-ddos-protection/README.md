# Enable Cloud Armor Advanced Network DDoS Protection

This example enables a advanced network DDoS protection in two regions. Advanced network DDoS protection is only availalable to projects enrolled in [Cloud Armor Enterprise](https://cloud.google.com/armor/docs/armor-enterprise-overview)

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
| adv\_ddos\_protection\_policies | n/a |
| network\_edge\_security\_services | n/a |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
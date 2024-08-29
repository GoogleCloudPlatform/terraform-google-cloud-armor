# Cloud Armor Policy end to end example

This example performs the following:
- Network (VPC/Subnets/Firewall-rules/NAT).
- A `global cloud armor security policy` with following types of rules.
  - Threat Intelligence Rules (Requires [Cloud Armor Enterprise](https://cloud.google.com/armor/docs/armor-enterprise-overview). Remove these rules if you dont have Cloud Armor Enterprise enabled for your project)
  - Rule for Automatically deploying Adaptive Protection suggested rules (Requires [Cloud Armor Enterprise](https://cloud.google.com/armor/docs/armor-enterprise-overview). Remove these rules if you dont have Cloud Armor Enterprise enabled for your project)
  - Pre-configured rules
  - Custom rules
  - Security rules
- A VM instance behind a `global external application load balancer`.
- Attaches `security policy` to the backend service  by passing security policy link in `security_policy` parameter in `google_compute_backend_service` resource.

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
| security\_policy | Cloud Armor security policy created |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

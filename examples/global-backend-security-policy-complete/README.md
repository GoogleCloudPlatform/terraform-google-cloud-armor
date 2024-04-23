# Cloud Armor Policy with preconfigured rules, custom rules and security rules

This example performs the following:
- Network (VPC/Subnets/Firewall-rules/NAT).
- Creates a `global cloud armor security policy`.
- Creates a VM instance behind a `global external application load balancer`.
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
| project\_id | The project ID |
| security\_policy | Cloud Armor security policy created |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

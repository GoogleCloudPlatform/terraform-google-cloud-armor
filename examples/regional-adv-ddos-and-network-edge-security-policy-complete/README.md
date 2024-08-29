# End to end example for Cloud Armor Advanced Network DDoS Protection & Network Edge Security Policy

Advanced network DDoS protection and network edge security policy is only available to projects enrolled in [Cloud Armor Enterprise](https://cloud.google.com/armor/docs/armor-enterprise-overview)

This example performs the following:
- Network (VPC/Subnets/Firewall-rules/NAT).
- Enables `advanced network DDoS protection` in two regions `us-central1` and `us-east1`.
- Creates a `network edge security policy` in `us-central1`.
- Creates a VM instance behind a `network load balancer`.
- Attaches `network edge security policy` to the backend service by passing security policy link in `security_policy` parameter in `google_compute_region_backend_service` resource.

## Usage

To run this example you need to execute:

```bash
YOUR_EXTERNAL_IP = "47.189.14.147/32"
export TF_VAR_project_id="your_project_id"
export TF_VAR_whitelisted_ingress_ip_ranges=[\"${YOUR_EXTERNAL_IP}\"]
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
| adv\_ddos\_protection\_policies | Advanced Network DDoS protection Security policies created |
| network\_edge\_security\_services | Network edge security services created |
| policy\_name | Name of Regional Network Security policy created |
| region | Name of Regional Network Security policy created |
| test\_nlb\_url | Use this command to test access to the load balancer. Try it from the IP address provided in rule 100 and a different IP address |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

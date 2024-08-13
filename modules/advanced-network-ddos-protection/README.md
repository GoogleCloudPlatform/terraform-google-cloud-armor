# Enable Cloud Armor Advanced Network DDoS Protection
This module enables [advanced network DDoS protection](https://cloud.google.com/armor/docs/armor-enterprise-overview#advanced_network_ddos_protection) in specified region(s). Advanced network DDoS protection is only availalable to projects enrolled in [Cloud Armor Enterprise](https://cloud.google.com/armor/docs/armor-enterprise-overview). Advanced network DDoS protection feature protects workloads using [external passthrough Network Load Balancers](https://cloud.google.com/load-balancing/docs/network), [protocol forwarding](https://cloud.google.com/load-balancing/docs/protocol-forwarding), or VMs with public IP addresses. When enabled for a particular region, Google Cloud Armor provides always-on targeted volumetric attack detection and mitigation for external passthrough Network Load Balancer, protocol forwarding, and VMs with public IP addresses in that region. This module creates security policy of type `CLOUD_ARMOR_NETWORK` and a a network edge security service in the specified region(s).

## Compatibility

This module is meant for use with Terraform 1.3+ and tested using Terraform 1.3+. If you find incompatibilities using Terraform >=1.3, please open an issue.

## Version

Current version is 0.X. Upgrade guides:

## Usage
There are examples included in the [examples](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/tree/main/examples) folder but simple usage is as follows:


```
module "advanced_network_ddos_protection" {
  source  = "GoogleCloudPlatform/cloud-armor/google//modules/advanced-network-ddos-protection"
  version = "~> 2.2"

  project_id  = var.project_id
  regions     = ["us-central1", "us-east1"]
}
```


<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| ddos\_protection\_config | Configuration for Google Cloud Armor DDOS Proctection Config. 1) ADVANCED: additional protections for Managed Protection Plus subscribers 2) ADVANCED\_PREVIEW: enable the security policy in preview mode | `string` | `"ADVANCED"` | no |
| network\_edge\_security\_service\_description | description of edge security service for advanced network ddos protection | `string` | `"edge security service for advanced network ddos protection"` | no |
| network\_edge\_security\_service\_name | Name of network edge security service resource for advanced network ddos protection | `string` | `"adv-network-ddos-protection"` | no |
| policy\_description | An optional description of advanced network ddos protection security policy | `string` | `"CA Advance DDoS protection"` | no |
| policy\_name | Name of the advanced network ddos protection security policy. Name must be 1-63 characters long and match the regular expression a-z? which means the first character must be a lowercase letter, and all following characters must be a dash, lowercase letter, or digit, except the last character, which cannot be a dash | `string` | `"adv-network-ddos-protection"` | no |
| project\_id | The project in which the resource belongs. | `string` | n/a | yes |
| regions | The regions in which advanced network DDoS protection will be activated | `list(string)` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| adv\_ddos\_protection\_policies | Advanced Network DDoS protection Security policies created |
| network\_edge\_security\_services | Network edge security services created |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

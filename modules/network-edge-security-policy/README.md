# Cloud Armor Terraform Module for Network Edge Security Policy
This module creates [network edge security policy](https://cloud.google.com/armor/docs/network-edge-policies) in specified region. Network edge security policy is only availalable to projects enrolled in [Cloud Armor Enterprise](https://cloud.google.com/armor/docs/armor-enterprise-overview) with [Advanced network DDoS protection](https://cloud.google.com/armor/docs/advanced-network-ddos#activate-advanced-ddos-protection) enabled. You can use [this sub-module](../advanced-network-ddos-protection/) to enable `advanced network ddos protection `.

You can attch network edge security policy to backend services of [external passthrough Network Load Balancers](https://cloud.google.com/load-balancing/docs/network). Network edge security policy supports [byte offset filtering](https://cloud.google.com/armor/docs/network-edge-policies#byte-offset). This module creates security policy of type `CLOUD_ARMOR_NETWORK` optionally attach security policy rules to the policy.

##  Module Format

```
module "network_edge_security_policy" {
  source  = "GoogleCloudPlatform/cloud-armor/google//modules/network-edge-security-policy"
  version = "~> 2.2"

  project_id  = var.project_id
  region      = "us-central1"
  policy_name = "test-nw-edge-security-policy"

  policy_user_defined_fields = [
    {},
    {},
  ]

  policy_rules = [
    {},
    {},
  ]
}
```

`policy_rules` details and Sample Code for each type of rule is available [here](#Rules)

## Usage
There are examples included in the [examples](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/tree/main/examples) folder but simple usage is as follows:


```
module "network_edge_security_policy" {
  source  = "GoogleCloudPlatform/cloud-armor/google//modules/network-edge-security-policy"
  version = "~> 2.0"

  project_id  = var.project_id
  region      = "us-central1"
  policy_name = "test-nw-edge-security-policy"

  policy_user_defined_fields = [
    {
      name   = "SIG1_AT_0"
      base   = "UDP"
      offset = 8
      size   = 2
      mask   = "0x8F00"
    },
    {
      name   = "SIG2_AT_8"
      base   = "TCP"
      offset = 16
      size   = 4
      mask   = "0xFFFFFFFF"
    },
  ]

  policy_rules = [
    {
      priority         = 100
      action           = "deny"
      preview          = true
      description      = "custom rule 100"
      src_ip_ranges    = ["10.10.0.0/16"]
      src_asns         = [15169]
      src_region_codes = ["AU"]
      ip_protocols     = ["TCP"]
      src_ports        = [80]
      dest_ports       = ["8080"]
      dest_ip_ranges   = ["10.100.0.0/16"]
      user_defined_fields = [
        {
          name   = "SIG1_AT_0"
          values = ["0x8F00"]
        },
      ]
    },
    {
      priority       = 200
      action         = "deny"
      preview        = false
      priority       = 200
      src_asns       = [15269]
      dest_ports     = ["80"]
      dest_ip_ranges = ["10.100.0.0/16"]
    },
  ]
}

## Backnd service to attach the security policy
resource "google_compute_region_backend_service" "backend" {
  provider              = google-beta

  ## Attach Cloud Armor policy to the backend service
  security_policy = module.network_edge_security_policy.security_policy.self_link

  project               = var.project_id
  name                  = "ca-website-backend-svc"
  region                = local.primary_region
  load_balancing_scheme = "EXTERNAL"
  health_checks         = [google_compute_region_health_check.default.id]
  backend {
    group = google_compute_instance_group.ca_vm_1_ig.self_link
  }

  log_config {
    enable      = true
    sample_rate = 0.5
  }
}

```


<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| policy\_description | An optional description of advanced network ddos protection security policy | `string` | `"CA Advance DDoS protection"` | no |
| policy\_name | Name of the advanced network ddos protection security policy. Name must be 1-63 characters long and match the regular expression a-z? which means the first character must be a lowercase letter, and all following characters must be a dash, lowercase letter, or digit, except the last character, which cannot be a dash | `string` | `"adv-network-ddos-protection"` | no |
| policy\_rules | Policy Rules | <pre>list(object({<br>    priority         = number<br>    action           = string<br>    preview          = optional(bool)<br>    description      = optional(string)<br>    ip_protocols     = optional(list(string))<br>    src_ip_ranges    = optional(list(string))<br>    src_asns         = optional(list(string))<br>    src_region_codes = optional(list(string))<br>    src_ports        = optional(list(string))<br>    dest_ports       = optional(list(string))<br>    dest_ip_ranges   = optional(list(string))<br><br>    user_defined_fields = optional(list(object({<br>      name   = optional(string)<br>      values = optional(list(string))<br>    })))<br>  }))</pre> | `null` | no |
| policy\_user\_defined\_fields | Definitions of user-defined fields for CLOUD\_ARMOR\_NETWORK policies. A user-defined field consists of up to 4 bytes extracted from a fixed offset in the packet, relative to the IPv4, IPv6, TCP, or UDP header, with an optional mask to select certain bits | <pre>list(object({<br>    name   = optional(string)<br>    base   = string<br>    offset = optional(number)<br>    size   = optional(number)<br>    mask   = optional(string)<br>  }))</pre> | `null` | no |
| project\_id | The project in which the resource belongs. | `string` | n/a | yes |
| region | The region in which enablesecurity policy is created | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| policy\_rules | Security policy rules created |
| security\_policy | Regional network Security policy created |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

## Rules

`policy_rules` is a list of objects with following parameters:
- `priority`: An integer indicating the priority of a rule in the list. The priority must be a positive value between 0 and 2147483647. Rules are evaluated from highest to lowest priority where 0 is the highest priority and 2147483647 is the lowest priority.
- `action`: The Action to perform when the rule is matched. The following are the valid actions:
  - allow: allow access to target.
  - deny(STATUS): deny access to target, returns the HTTP response code specified. Valid values for STATUS are 403, 404, and 502.
- `preview`: If set to true, the specified action is not enforced
- `description`: An optional description of this resource. Provide this property when you create the resource
- `src_ip_ranges`: list of source IPv4/IPv6 addresses or CIDR prefixes, in standard text format
- `src_asns`: list of BGP Autonomous System Number associated with the source IP address
- `src_region_codes`: list of Two-letter ISO 3166-1 alpha-2 country code associated with the source IP address
- `ip_protocols`: list of IPv4 protocol / IPv6 next header (after extension headers). Each element can be an 8-bit unsigned decimal number (e.g. "6"), range (e.g. "253-254"), or one of the following protocol names: "tcp", "udp", "icmp", "esp", "ah", "ipip", or "sctp"
- `src_ports`: Source port numbers for TCP/UDP/SCTP. Each element can be a 16-bit unsigned decimal number (e.g. "80") or range (e.g. "0-1023")
- `dest_ports`: Destination port numbers for TCP/UDP/SCTP. Each element can be a 16-bit unsigned decimal number (e.g. "80") or range (e.g. "0-1023")
- `dest_ip_ranges`: Destination IPv4/IPv6 addresses or CIDR prefixes, in standard text format
- `user_defined_fields`:User-defined fields. Each element names a defined field and lists the matching values for that field. Support following fields:
  - `name`: Name of the user-defined field, as given in the definition
  - `values`: Matching values of the field. Each element can be a 32-bit unsigned decimal or hexadecimal (starting with "0x") number (e.g. "64") or range (e.g. "0x400-0x7ff")

### Format:

```
[
  {
    priority         = 100
    action           = "deny"
    preview          = true
    description      = "custom rule 100"
    src_ip_ranges    = ["10.10.0.0/16"]
    src_asns         = [15169]
    src_region_codes = ["AU"]
    ip_protocols     = ["TCP"]
    src_ports        = [80]
    dest_ports       = ["8080"]
    dest_ip_ranges   = ["10.100.0.0/16"]
    user_defined_fields = [
      {},
    ]
  },
]
```


### Sample:

```
  policy_rules = [
    {
      priority         = 100
      action           = "deny"
      preview          = true
      description      = "custom rule 100"
      src_ip_ranges    = ["10.10.0.0/16"]
      src_asns         = [15169]
      src_region_codes = ["AU"]
      ip_protocols     = ["TCP"]
      src_ports        = [80]
      dest_ports       = ["8080"]
      dest_ip_ranges   = ["10.100.0.0/16"]
      user_defined_fields = [
        {
          name   = "SIG1_AT_0"
          values = ["0x8F00"]
        },
      ]
    },
    {
      priority       = 200
      action         = "deny"
      preview        = false
      priority       = 200
      src_asns       = [15269]
      dest_ports     = ["80"]
      dest_ip_ranges = ["10.100.0.0/16"]
    },
  ]
```

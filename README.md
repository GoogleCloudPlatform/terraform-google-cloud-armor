# Cloud Armor Terraform Module
This module makes it easy to setup [Cloud Armor Security Policy](https://cloud.google.com/armor/docs/cloud-armor-overview#security_policies) with Security rules. There are four type of rules you can create in each policy:
- [Pre-Configured Rules](#pre_conf_rules): These are based on [pre-configured waf rules](https://cloud.google.com/armor/docs/waf-rules)
- [Security Rules](#security_rules): Allow or Deny traffice from set of IP addresses
- [Custom Rules](#custom_rules): You can create your own rules using [Common Expression Language (CEL)](https://cloud.google.com/armor/docs/rules-language-reference)
- [Threat Intelligence Rules](#threat_intelligence_rules): Add Rules based on [threat intelligence](https://cloud.google.com/armor/docs/threat-intelligence). You need to have managed protection plus enable to use this feature


## Compatibility

This module is meant for use with Terraform 1.3+ and tested using Terraform 1.3+. If you find incompatibilities using Terraform >=0.13, please open an issue.

## Usage
There are examples included in the [examples](https://github.com/terraform-google-modules/terraform-google-cloud-armor/tree/master/examples) folder but simple usage is as follows:


```
module "security_policy" {
  source = "GoogleCloudPlatform/cloud-armor/google"
  version = "~> 1.0"

  project_id                           = var.project_id
  name                                 = var.name
  description                          = var.description
  default_rule_action                  = var.default_rule_action
  type                                 = "CLOUD_ARMOR"
  layer_7_ddos_defense_enable          = true
  layer_7_ddos_defense_rule_visibility = "STANDARD"


  pre_configured_rules = {
    "sqli_sensitivity_level_4" = {
      action          = "deny(502)"
      priority        = 1
      target_rule_set = "sqli-v33-stable"
    }

    "xss-stable_level_2_with_exclude" = {
      action                  = "throttle"
      priority                = 2
      description             = "XSS Sensitivity Level 2 with excluded rules"
      preview                 = true
      target_rule_set         = "xss-v33-stable"
      sensitivity_level       = 2
      exclude_target_rule_ids = ["owasp-crs-v030301-id941380-xss", "owasp-crs-v030301-id941340-xss"]
      rate_limit_options = {
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
      }
    }

    "php-stable_level_1_with_include" = {
      action                  = "rate_based_ban"
      priority                = 3
      description             = "PHP Sensitivity Level 1 with included rules"
      target_rule_set         = "xss-v33-stable"
      sensitivity_level       = 0
      include_target_rule_ids = ["owasp-crs-v030301-id933190-php", "owasp-crs-v030301-id933111-php"]
      exclude_target_rule_ids = []
      rate_limit_options = {
        ban_duration_sec                     = 600
        enforce_on_key                       = "ALL"
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
        ban_http_request_count               = 1000
        ban_http_request_interval_sec        = 300
      }
    }

    "rfi_sensitivity_level_4" = {
      action          = "redirect"
      priority        = 4
      description     = "Remote file inclusion 4"
      redirect_type   = "GOOGLE_RECAPTCHA"
      target_rule_set = "rfi-v33-stable"
    }

  }

  security_rules = {
    "deny_project_honeypot" = {
      action        = "deny(502)"
      priority      = 11
      description   = "Deny Malicious IP address from project honeypot"
      src_ip_ranges = ["190.217.68.211", "45.116.227.68", "103.43.141.122", "123.11.215.36", ]
      preview       = true
    }

    "redirect_project_drop" = {
      action        = "redirect"
      priority      = 12
      description   = "Redirect IP address from project drop"
      src_ip_ranges = ["190.217.68.212", "45.116.227.69", ]
      redirect_type = "GOOGLE_RECAPTCHA"
    }

    "rate_ban_project_dropten" = {
      action        = "rate_based_ban"
      priority      = 13
      description   = "Rate based ban for address from project dropten as soon as they cross rate limit threshold"
      src_ip_ranges = ["190.217.68.213", "45.116.227.70", ]
      rate_limit_options = {
        ban_duration_sec                     = 120
        enforce_on_key                       = "ALL"
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
      }
    }

    "rate_ban_project_dropthirty" = {
      action        = "rate_based_ban"
      priority      = 14
      description   = "Rate based ban for address from project dropthirty only if they cross banned threshold"
      src_ip_ranges = ["190.217.68.213", "45.116.227.70", ]
      rate_limit_options = {
        ban_duration_sec                     = 300
        enforce_on_key                       = "ALL"
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
        ban_http_request_count               = 1000
        ban_http_request_interval_sec        = 300
      }
    }

    "throttle_project_droptwenty" = {
      action        = "throttle"
      priority      = 15
      description   = "Throttle IP addresses from project droptwenty"
      src_ip_ranges = ["190.217.68.214", "45.116.227.71", ]
      rate_limit_options = {
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
      }
    }
  }

  custom_rules = {
    allow_specific_regions = {
      action      = "allow"
      priority    = 21
      description = "Allow specific Regions"
      expression  = <<-EOT
        '[US,AU,BE]'.contains(origin.region_code)
      EOT
    }

    deny_specific_ip = {
      action      = "deny(502)"
      priority    = 22
      description = "Deny Specific IP address"
      expression  = <<-EOT
        inIpRange(origin.ip, '47.185.201.155/32')
      EOT
    }
    throttle_specific_ip = {
      action      = "throttle"
      priority    = 23
      description = "Throttle specific IP address in US Region"
      expression  = <<-EOT
        origin.region_code == "US" && inIpRange(origin.ip, '47.185.201.159/32')
      EOT
      rate_limit_options = {
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
      }
    }
    rate_ban_specific_ip = {
      action     = "rate_based_ban"
      priority   = 24
      expression = <<-EOT
        inIpRange(origin.ip, '47.185.201.160/32')
      EOT
      rate_limit_options = {
        ban_duration_sec                     = 120
        enforce_on_key                       = "ALL"
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
        ban_http_request_count               = 10000
        ban_http_request_interval_sec        = 600
      }
    }
    test-sl = {
      action      = "deny(502)"
      priority    = 100
      description = "test Sensitivity level policies"
      preview     = true
      expression  = <<-EOT
        evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 4, 'opt_out_rule_ids': ['owasp-crs-v030301-id942350-sqli', 'owasp-crs-v030301-id942360-sqli']})
      EOT
    }
  }

  ##  threat_intelligence_rules needs manage protection plus
  threat_intelligence_rules = {
    deny_crawlers_ip = {
      action             = "deny(502)"
      priority           = 31
      description        = "Deny IP addresses of search engine crawlers"
      preview            = false
      feed               = "iplist-search-engines-crawlers" #https://cloud.google.com/armor/docs/threat-intelligence#configure-nti
      redirect_type      = null
      rate_limit_options = {}
    }
  }

}

```


<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| custom\_rules | Custome security rules | <pre>map(object({<br>    action        = string<br>    priority      = number<br>    description   = optional(string)<br>    preview       = optional(bool, false)<br>    expression    = string<br>    redirect_type = optional(string, null)<br>    rate_limit_options = optional(object({<br>      enforce_on_key                       = optional(string)<br>      exceed_action                        = optional(string)<br>      rate_limit_http_request_count        = optional(number)<br>      rate_limit_http_request_interval_sec = optional(number)<br>      ban_duration_sec                     = optional(number)<br>      ban_http_request_count               = optional(number)<br>      ban_http_request_interval_sec        = optional(number)<br>      }),<br>    {})<br>  }))</pre> | `{}` | no |
| default\_rule\_action | default rule that allows/denies all traffic with the lowest priority (2,147,483,647) | `string` | `"allow"` | no |
| description | An optional description of this security policy. Max size is 2048. | `string` | `null` | no |
| layer\_7\_ddos\_defense\_enable | (Optional) If set to true, enables CAAP for L7 DDoS detection | `bool` | `false` | no |
| layer\_7\_ddos\_defense\_rule\_visibility | (Optional) Rule visibility can be one of the following: STANDARD - opaque rules. PREMIUM - transparent rules | `string` | `"STANDARD"` | no |
| name | Name of the security policy. | `string` | n/a | yes |
| pre\_configured\_rules | Map of pre-configured rules Sensitivity levels | <pre>map(object({<br>    action                  = string<br>    priority                = number<br>    description             = optional(string)<br>    preview                 = optional(bool, false)<br>    redirect_type           = optional(string, null)<br>    target_rule_set         = string<br>    sensitivity_level       = optional(number, 4)<br>    include_target_rule_ids = optional(list(string), [])<br>    exclude_target_rule_ids = optional(list(string), [])<br>    rate_limit_options = optional(object({<br>      enforce_on_key                       = optional(string)<br>      exceed_action                        = optional(string)<br>      rate_limit_http_request_count        = optional(number)<br>      rate_limit_http_request_interval_sec = optional(number)<br>      ban_duration_sec                     = optional(number)<br>      ban_http_request_count               = optional(number)<br>      ban_http_request_interval_sec        = optional(number)<br>      }),<br>    {})<br>  }))</pre> | `{}` | no |
| project\_id | The project in which the resource belongs | `string` | n/a | yes |
| security\_rules | Map of Security rules with list of IP addresses to block or unblock | <pre>map(object({<br>    action        = string<br>    priority      = number<br>    description   = optional(string)<br>    preview       = optional(bool, false)<br>    redirect_type = optional(string, null)<br>    src_ip_ranges = list(string)<br>    rate_limit_options = optional(object({<br>      enforce_on_key                       = optional(string)<br>      exceed_action                        = optional(string)<br>      rate_limit_http_request_count        = optional(number)<br>      rate_limit_http_request_interval_sec = optional(number)<br>      ban_duration_sec                     = optional(number)<br>      ban_http_request_count               = optional(number)<br>      ban_http_request_interval_sec        = optional(number)<br>      }),<br>    {})<br>  }))</pre> | `{}` | no |
| threat\_intelligence\_rules | Map of Threat Intelligence Feed rules | `map(any)` | `{}` | no |
| type | Type indicates the intended use of the security policy. Possible values are CLOUD\_ARMOR and CLOUD\_ARMOR\_EDGE | `string` | `"CLOUD_ARMOR"` | no |

## Outputs

| Name | Description |
|------|-------------|
| policy | Security policy created |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->



##  Module Format

```
module security_polcy {
  source = "terraform-google-modules/cloud-armor/google"

  project_id                   = "my-project-id"
  name                         = my-test-ca-policy
  description                  = "Test Cloud Armor security policy with preconfigured rules, security rules and custom rules"
  default_rule_action          = "deny(403)"
  pre_configured_rules         = {}
  security_rules               = {}
  custom_rules                 = {}
  threat_intelligence_rules    = {}
}
```

###  Rules
`pre_configured_rules`, `security_rules`, `custom_rules` and `threat_intelligence_rules` are maps of rules. Each rule is a map of strings which provides details about the rule. For example:

```
  "my_rule" = {
    action                  = "deny(502)"
    priority                = 1
    description             = "SQL Sensitivity Level 4"
    preview                 = false
    redirect_type           = null
    target_rule_set         = "sqli-v33-stable"
    sensitivity_level       = 4
    include_target_rule_ids = []
    exclude_target_rule_ids = []
    rate_limit_options      = {}
  }
```

### Rate limit options
`rate_limit_options` is a map of strings with following key pairs. You can find more details about rate limit [here](https://cloud.google.com/armor/docs/rate-limiting-overview)

```
rate_limit_options = {
  ban_duration_sec                     = 600    # needed only if action is rate_based_ban
  enforce_on_key                       = "ALL"  # All is default value. If null is passed terraform will use ALL as the value
  exceed_action                        = "deny(502)"
  rate_limit_http_request_count        = 10
  rate_limit_http_request_interval_sec = 60    # must be one of 60, 120, 180, 240, 300, 600, 900, 1200, 1800, 2700, 3600 seconds
  ban_http_request_count               = 1000
  ban_http_request_interval_sec        = 300   # must be one of 60, 120, 180, 240, 300, 600, 900, 1200, 1800, 2700, 3600 seconds
}
```

##  pre_conf_rules
List of preconfigured rules are available [here](https://cloud.google.com/armor/docs/waf-rules). Following is the key value pairs for setting up pre configured rules

###  Format:

```
  "sqli_sensitivity_level_4" = {
    action                  = "deny(502)"
    priority                = 1
    description             = "SQL Sensitivity Level 4"
    preview                 = false
    redirect_type           = null
    target_rule_set         = "sqli-v33-stable"
    sensitivity_level       = 4
    include_target_rule_ids = []
    exclude_target_rule_ids = []
    rate_limit_options      = {}
  }
```


###  Sample:
```
pre_configured_rules = {
  "php-stable_level_1_with_include" = {
    action                  = "rate_based_ban"
    priority                = 3
    description             = "PHP Sensitivity Level 1 with included rules"
    preview                 = false
    redirect_type           = null
    target_rule_set         = "xss-v33-stable"
    sensitivity_level       = 0
    include_target_rule_ids = ["owasp-crs-v030301-id933190-php", "owasp-crs-v030301-id933111-php"]
    exclude_target_rule_ids = []
    rate_limit_options = {
      ban_duration_sec                     = 600
      enforce_on_key                       = "ALL"
      exceed_action                        = "deny(502)"
      rate_limit_http_request_count        = 10
      rate_limit_http_request_interval_sec = 60
      ban_http_request_count               = 1000
      ban_http_request_interval_sec        = 300
    }
  }
  "rfi_sensitivity_level_4" = {
    action                  = "redirect"
    priority                = 4
    description             = "Remote file inclusion 4"
    preview                 = false
    redirect_type           = "GOOGLE_RECAPTCHA"
    target_rule_set         = "rfi-v33-stable"
    sensitivity_level       = 4
    include_target_rule_ids = []
    exclude_target_rule_ids = []
    rate_limit_options      = {}
  }
}
```


##  security_rules:
Set of IP addresses or ranges (IPV4 or IPV6) in CIDR notation to match against inbound traffic. There is a limit of 10 IP ranges per rule.

###  Format:
Each rule is key value pair where key is a unique name of the rule and value is the action associated with it.

```
"block_bad_actor_ip" = {
  action             = "deny(502)"
  priority           = 11
  description        = "Deny Malicious IP address"
  src_ip_ranges      = ["A..B.C.D", "W.X.Y.Z",]
  preview            = false
  redirect_type      = null
  rate_limit_options = {}
}
```

###  Sample:
```
security_rules = {
  "deny_project_honeypot" = {
    action             = "deny(502)"
    priority           = 11
    description        = "Deny Malicious IP address from project honeypot"
    src_ip_ranges      = ["190.217.68.211", "45.116.227.68", "103.43.141.122", "123.11.215.36", ]
    preview            = false
    redirect_type      = null
    rate_limit_options = {}
  }
  "throttle_project_droptwenty" = {
    action        = "throttle"
    priority      = 15
    description   = "Throttle IP addresses from project droptwenty"
    src_ip_ranges = ["190.217.68.214", "45.116.227.71", ]
    preview       = false
    redirect_type = null
    rate_limit_options = {
      exceed_action                        = "deny(502)"
      rate_limit_http_request_count        = 10
      rate_limit_http_request_interval_sec = 60
    }
  }
}
```

##  custom_rules:
Add Custom Rules using [Common Expression Language (CEL)](https://cloud.google.com/armor/docs/rules-language-reference)

###  Format:
Each rule is key value pair where key is a unique name of the rule and value is the action associated with it.
```
allow_specific_regions = {
  action             = "allow"
  priority           = 21
  description        = "Allow specific Regions"
  preview            = false
  expression         = <<-EOT
    '[US,AU,BE]'.contains(origin.region_code)
  EOT
  redirect_type      = null
  rate_limit_options = {}
}
```

###  Sample:
```
custom_rules = {
  allow_specific_regions = {
    action             = "allow"
    priority           = 21
    description        = "Allow specific Regions"
    preview            = false
    expression         = <<-EOT
      '[US,AU,BE]'.contains(origin.region_code)
    EOT
    redirect_type      = null
    rate_limit_options = {}
  }
  test-sl = {
    action             = "deny(502)"
    priority           = 100
    description        = "test Sensitivity level policies"
    preview            = false
    expression         = <<-EOT
      evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 4, 'opt_out_rule_ids': ['owasp-crs-v030301-id942350-sqli', 'owasp-crs-v030301-id942360-sqli']})
    EOT
    redirect_type      = null
    rate_limit_options = {}
  }
}
```

##  threat_intelligence_rules:
Add Rules based on [threat intelligence](https://cloud.google.com/armor/docs/threat-intelligence). You need to enable [managed protection plus](https://cloud.google.com/armor/docs/managed-protection-overview#standard_versus_plus) to use this feature

###  Format:
Each rule is key value pair where key is a unique name of the rule and value is the action associated with it.
```
threat_intelligence_rules = {
  deny_crawlers_ip = {
    action             = "deny(502)"
    priority           = 31
    description        = "Deny IP addresses of search engine crawlers"
    preview            = false
    feed               = "iplist-search-engines-crawlers" #https://cloud.google.com/armor/docs/threat-intelligence#configure-nti
    redirect_type      = null
    rate_limit_options = {}
  }
}
```

###  Sample:
```
threat_intelligence_rules = {
  deny_crawlers_ip = {
    action             = "deny(502)"
    priority           = 31
    description        = "Deny IP addresses of search engine crawlers"
    preview            = false
    feed               = "iplist-search-engines-crawlers" #https://cloud.google.com/armor/docs/threat-intelligence#configure-nti
    redirect_type      = null
    rate_limit_options = {}
  }
}
```

## Requirements

These sections describe requirements for using this module.

### Software

The following dependencies must be available:

- [Terraform][terraform] v1.3+
- [Terraform Provider for GCP][terraform-provider-gcp] plugin v4.39+

### Service Account

A service account with the following permission must be used to provision
the resources of this module:

- compute.securityPolicies.create
- compute.securityPolicies.delete
- compute.securityPolicies.get
- compute.securityPolicies.list
- compute.securityPolicies.use
- compute.securityPolicies.update

Following roles contain above mentioned permissions. You can either assing one of the following role or create custom roles with above permissions.

- Compute Organization Security Policy Admin: `roles/compute.orgSecurityPolicyAdmin`
- Compute Security Admin: `roles/compute.securityAdmin`

### Enable API's
In order to operate with the Service Account you must activate the following API on the project where the Service Account was created:

- Compute Engine API - compute.googleapis.com

## Contributing

Refer to the [contribution guidelines](./CONTRIBUTING.md) for
information on contributing to this module.

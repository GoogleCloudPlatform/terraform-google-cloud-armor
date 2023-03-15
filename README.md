# Cloud Armor Terraform Module
This module makes it easy to setup [Cloud Armor Security Policy](https://cloud.google.com/armor/docs/cloud-armor-overview#security_policies) with Security rules. There are four type of rules you can create in each policy:
- [Pre-Configured Rules](#pre_configured_rules): These are based on [pre-configured waf rules](https://cloud.google.com/armor/docs/waf-rules).
- [Security Rules](#security_rules): Allow or Deny traffic from list of IP addresses or IP adress ranges.
- [Custom Rules](#custom_rules): You can create your own rules using [Common Expression Language (CEL)](https://cloud.google.com/armor/docs/rules-language-reference).
- [Threat Intelligence Rules](#threat_intelligence_rules): Add Rules based on [threat intelligence](https://cloud.google.com/armor/docs/threat-intelligence). [Managed protection plus](https://cloud.google.com/armor/docs/managed-protection-overview) subscription is needed to use this feature.


## Compatibility

This module is meant for use with Terraform 1.3+ and tested using Terraform 1.3+. If you find incompatibilities using Terraform >=1.3, please open an issue.

##  Module Format

```
module security_polcy {
  source = "GoogleCloudPlatform/cloud-armor/google"

  project_id                   = "my-project-id"
  name                         = my-test-ca-policy
  description                  = "Test Cloud Armor security policy with preconfigured rules, security rules and custom rules"
  default_rule_action          = "deny(403)"
  recaptcha_redirect_site_key  = google_recaptcha_enterprise_key.primary.name
  pre_configured_rules         = {}
  security_rules               = {}
  custom_rules                 = {}
  threat_intelligence_rules    = {}
}
```

Rule details and Sample Code for each type of rule is available [here](#Rules)

## Usage
There are examples included in the [examples](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/tree/main/examples) folder but simple usage is as follows:

```
module "security_policy" {
  source = "GoogleCloudPlatform/cloud-armor/google"
  version = "~> 0.2"

  project_id                           = var.project_id
  name                                 = "my-test-security-policy"
  description                          = "Test Security Policy"
  recaptcha_redirect_site_key          = google_recaptcha_enterprise_key.primary.name
  default_rule_action                  = "allow"
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
      action                  = "deny(502)"
      priority                = 2
      description             = "XSS Sensitivity Level 2 with excluded rules"
      preview                 = true
      target_rule_set         = "xss-v33-stable"
      sensitivity_level       = 2
      exclude_target_rule_ids = ["owasp-crs-v030301-id941380-xss", "owasp-crs-v030301-id941280-xss"]
    }

    "php-stable_level_0_with_include" = {
      action                  = "deny(502)"
      priority                = 3
      description             = "PHP Sensitivity Level 0 with included rules"
      target_rule_set         = "php-v33-stable"
      include_target_rule_ids = ["owasp-crs-v030301-id933190-php", "owasp-crs-v030301-id933111-php"]
    }

  }

  security_rules = {

    "deny_project_bad_actor1" = {
      action        = "deny(502)"
      priority      = 11
      description   = "Deny Malicious IP address from project bad_actor1"
      src_ip_ranges = ["190.217.68.211/32", "45.116.227.68/32", "103.43.141.122/32", "123.11.215.36", "123.11.215.37", ]
      preview       = true
    }

    "redirect_project_rd" = {
      action        = "redirect"
      priority      = 12
      description   = "Redirect IP address from project RD"
      src_ip_ranges = ["190.217.68.215", "45.116.227.99", ]
      redirect_type = "EXTERNAL_302"
      redirect_target = "https://www.example.com"
    }

    "rate_ban_project_actor2" = {
      action        = "rate_based_ban"
      priority      = 13
      description   = "Rate based ban for address from project actor2 as soon as they cross rate limit threshold"
      src_ip_ranges = ["190.217.68.213/32", "45.116.227.70", ]
      rate_limit_options = {
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
        ban_duration_sec                     = 120
        enforce_on_key                       = "ALL"
      }
    }

    "rate_ban_project_actor3" = {
      action        = "rate_based_ban"
      priority      = 14
      description   = "Rate based ban for address from project actor3 only if they cross banned threshold"
      src_ip_ranges = ["190.217.68.213", "45.116.227.70", ]
      rate_limit_options = {
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
        ban_duration_sec                     = 600
        ban_http_request_count               = 1000
        ban_http_request_interval_sec        = 300
        enforce_on_key                       = "ALL"
      }
    }

    "throttle_project_actor4" = {
      action        = "throttle"
      priority      = 15
      description   = "Throttle IP addresses from project actor4"
      src_ip_ranges = ["190.217.68.214", "45.116.227.71", ]
      rate_limit_options = {
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
      }
    }

  }

  custom_rules = {

    deny_specific_regions = {
      action      = "deny(502)"
      priority    = 21
      description = "Deny specific Regions"
      expression  = <<-EOT
        '[AU,BE]'.contains(origin.region_code)
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

    throttle_specific_ip_region = {
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
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
        ban_duration_sec                     = 120
        ban_http_request_count               = 10000
        ban_http_request_interval_sec        = 600
        enforce_on_key                       = "ALL"
      }
    }

    allow_path_token_header = {
      action      = "allow"
      priority    = 25
      description = "Allow path and token match with addition of header"

      expression = <<-EOT
        request.path.matches('/login.html') && token.recaptcha_session.score < 0.2
      EOT

      header_action = [
        {
          header_name  = "reCAPTCHA-Warning"
          header_value = "high"
        },
        {
          header_name  = "X-Resource"
          header_value = "test"
        }
      ]

    }

    deny_java_level3_with_exclude = {
      action      = "deny(502)"
      priority    = 100
      description = "Deny pre-configured rule java-v33-stable at sensitivity level 3"
      preview     = true
      expression  = <<-EOT
        evaluatePreconfiguredWaf('java-v33-stable', {'sensitivity': 3, 'opt_out_rule_ids': ['owasp-crs-v030301-id944240-java', 'owasp-crs-v030301-id944120-java']})
      EOT
    }

  }

}
```


<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| custom\_rules | Custome security rules | <pre>map(object({<br>    action          = string<br>    priority        = number<br>    description     = optional(string)<br>    preview         = optional(bool, false)<br>    expression      = string<br>    redirect_type   = optional(string, null)<br>    redirect_target = optional(string, null)<br>    rate_limit_options = optional(object({<br>      enforce_on_key                       = optional(string)<br>      exceed_action                        = optional(string)<br>      rate_limit_http_request_count        = optional(number)<br>      rate_limit_http_request_interval_sec = optional(number)<br>      ban_duration_sec                     = optional(number)<br>      ban_http_request_count               = optional(number)<br>      ban_http_request_interval_sec        = optional(number)<br>      }),<br>    {})<br>    header_action = optional(list(object({<br>      header_name  = optional(string)<br>      header_value = optional(string)<br>    })), [])<br>  }))</pre> | `{}` | no |
| default\_rule\_action | default rule that allows/denies all traffic with the lowest priority (2,147,483,647) | `string` | `"allow"` | no |
| description | An optional description of this security policy. Max size is 2048. | `string` | `null` | no |
| json\_custom\_config\_content\_types | A list of custom Content-Type header values to apply the JSON parsing. Only applicable when json\_parsing is set to STANDARD | `list(string)` | `[]` | no |
| json\_parsing | Whether or not to JSON parse the payload body. Possible values are DISABLED and STANDARD. Defaults to DISABLED | `string` | `"DISABLED"` | no |
| layer\_7\_ddos\_defense\_enable | (Optional) If set to true, enables CAAP for L7 DDoS detection | `bool` | `false` | no |
| layer\_7\_ddos\_defense\_rule\_visibility | (Optional) Rule visibility can be one of the following: STANDARD - opaque rules. PREMIUM - transparent rules | `string` | `"STANDARD"` | no |
| log\_level | Log level to use. Possible values are NORMAL and VERBOSE. Defaults to NORMAL | `string` | `"NORMAL"` | no |
| name | Name of the security policy. | `string` | n/a | yes |
| pre\_configured\_rules | Map of pre-configured rules Sensitivity levels | <pre>map(object({<br>    action                  = string<br>    priority                = number<br>    description             = optional(string)<br>    preview                 = optional(bool, false)<br>    redirect_type           = optional(string, null)<br>    redirect_target         = optional(string, null)<br>    target_rule_set         = string<br>    sensitivity_level       = optional(number, 4)<br>    include_target_rule_ids = optional(list(string), [])<br>    exclude_target_rule_ids = optional(list(string), [])<br>    rate_limit_options = optional(object({<br>      enforce_on_key                       = optional(string)<br>      exceed_action                        = optional(string)<br>      rate_limit_http_request_count        = optional(number)<br>      rate_limit_http_request_interval_sec = optional(number)<br>      ban_duration_sec                     = optional(number)<br>      ban_http_request_count               = optional(number)<br>      ban_http_request_interval_sec        = optional(number)<br>      }),<br>    {})<br>    header_action = optional(list(object({<br>      header_name  = optional(string)<br>      header_value = optional(string)<br>    })), [])<br>  }))</pre> | `{}` | no |
| project\_id | The project in which the resource belongs | `string` | n/a | yes |
| recaptcha\_redirect\_site\_key | reCAPTCHA site key to be used for all the rules using the redirect action with the redirect type of GOOGLE\_RECAPTCHA | `string` | `null` | no |
| security\_rules | Map of Security rules with list of IP addresses to block or unblock | <pre>map(object({<br>    action          = string<br>    priority        = number<br>    description     = optional(string)<br>    preview         = optional(bool, false)<br>    redirect_type   = optional(string, null)<br>    redirect_target = optional(string, null)<br>    src_ip_ranges   = list(string)<br>    rate_limit_options = optional(object({<br>      enforce_on_key                       = optional(string)<br>      exceed_action                        = optional(string)<br>      rate_limit_http_request_count        = optional(number)<br>      rate_limit_http_request_interval_sec = optional(number)<br>      ban_duration_sec                     = optional(number)<br>      ban_http_request_count               = optional(number)<br>      ban_http_request_interval_sec        = optional(number)<br>      }),<br>    {})<br>    header_action = optional(list(object({<br>      header_name  = optional(string)<br>      header_value = optional(string)<br>    })), [])<br>  }))</pre> | `{}` | no |
| threat\_intelligence\_rules | Map of Threat Intelligence Feed rules | `map(any)` | `{}` | no |
| type | Type indicates the intended use of the security policy. Possible values are CLOUD\_ARMOR and CLOUD\_ARMOR\_EDGE | `string` | `"CLOUD_ARMOR"` | no |

## Outputs

| Name | Description |
|------|-------------|
| policy | Security policy created |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->



## Rules

[Pre-Configured Rules](#pre_configured_rules), [Security Rules](#security_rules), [Custom Rules](#custom_rules) and [Threat Intelligence Rules](#threat_intelligence_rules) are maps of rules. Each rule is a map which provides details about the rule. Here is an example of `pre_configured_rules`:

```
  "my_rule" = {
    action                  = "deny(502)"
    priority                = 1
    description             = "SQL Sensitivity Level 4"
    preview                 = false
    redirect_type           = null
    redirect_target         = null
    target_rule_set         = "sqli-v33-stable"
    sensitivity_level       = 4
    include_target_rule_ids = []
    exclude_target_rule_ids = []
    rate_limit_options      = {}
    header_action           = []
  }
```

`action, priority, description, preview, rate_limit_options, header_action, redirect_type and redirect_target` are common in all the rule types. Some of then are optional and some have default value see [Input](#Inputs).

## Rate limit
`rate_limit_options` is needed for the rules where action is set to `throttle` or `rate_based_ban`. `rate_limit_options` is a map of strings with following key pairs. You can find more details about rate limit [here](https://cloud.google.com/armor/docs/rate-limiting-overview)

```
rate_limit_options = {
  exceed_action                        = "deny(502)"
  rate_limit_http_request_count        = 10
  rate_limit_http_request_interval_sec = 60    # must be one of 60, 120, 180, 240, 300, 600, 900, 1200, 1800, 2700, 3600 seconds
  ban_duration_sec                     = 600   # needed only if action is rate_based_ban
  ban_http_request_count               = 1000  # needed only if action is rate_based_ban
  ban_http_request_interval_sec        = 300   # must be one of 60, 120, 180, 240, 300, 600, 900, 1200, 1800, 2700, 3600 seconds. needed only if action is rate_based_ban
  enforce_on_key                       = "ALL" # All is default value. If null is passed terraform will use ALL as the value
}
```

## pre_configured_rules
List of preconfigured rules are available [here](https://cloud.google.com/armor/docs/waf-rules). Following is the key value pairs for setting up pre configured rules. `include_target_rule_ids` and `exclude_target_rule_ids` are mutually exclusive. If `include_target_rule_ids` is provided, sensitivity_level is automatically set to 0 by the module as it is a [requirement for opt in rule signature](https://cloud.google.com/armor/docs/rule-tuning#opt_in_rule_signatures). `exclude_target_rule_ids` is ignored when `include_target_rule_ids` is provided.

### Format:

```
  "sqli_sensitivity_level_4" = {
    action                  = "deny(502)"
    priority                = 1
    description             = "SQL Sensitivity Level 4"
    preview                 = false
    redirect_type           = null
    redirect_target         = null
    target_rule_set         = "sqli-v33-stable"
    sensitivity_level       = 4
    include_target_rule_ids = []
    exclude_target_rule_ids = []
    rate_limit_options      = {}
    header_action           = []
  }
```


### Sample:

```
pre_configured_rules = {

  "php-stable_level_1_with_include" = {
    action                  = "deny(502)"
    priority                = 3
    description             = "PHP Sensitivity Level 1 with included rules"
    target_rule_set         = "xss-v33-stable"
    sensitivity_level       = 0
    include_target_rule_ids = ["owasp-crs-v030301-id933190-php", "owasp-crs-v030301-id933111-php"]
  }

  "rfi_sensitivity_level_4" = {
    action                  = "redirect"
    priority                = 4
    description             = "Remote file inclusion 4"
    preview                 = true
    redirect_type           = "GOOGLE_RECAPTCHA"
    target_rule_set         = "rfi-v33-stable"
    sensitivity_level       = 4
  }

}
```


## security_rules:
Set of IP addresses or ranges (IPV4 or IPV6) in CIDR notation to match against inbound traffic. There is a limit of 10 IP ranges per rule.

### Format:
Each rule is key value pair where key is a unique name of the rule and value is the action associated with it.

```
"block_bad_actor_ip" = {
  action             = "deny(502)"
  priority           = 11
  description        = "Deny Malicious IP address"
  src_ip_ranges      = ["A..B.C.D", "W.X.Y.Z",]
  preview            = false
  redirect_type      = null
  redirect_target    = null
  rate_limit_options = {}
  header_action      = []
}
```

### Sample:

```
security_rules = {

  "deny_project_bad_actor" = {
    action             = "deny(502)"
    priority           = 11
    description        = "Deny Malicious IP address from project bad_actor"
    src_ip_ranges      = ["190.217.68.211", "45.116.227.68", "103.43.141.122", "123.11.215.36", ]
  }

  "throttle_project_bad_actor4" = {
    action        = "throttle"
    priority      = 15
    description   = "Throttle IP addresses from project bad_actor4"
    src_ip_ranges = ["190.217.68.214", "45.116.227.71", ]
    preview       = true
    rate_limit_options = {
      exceed_action                        = "deny(502)"
      rate_limit_http_request_count        = 10
      rate_limit_http_request_interval_sec = 60
    }
  }

}
```

## custom_rules:
Add Custom Rules using [Common Expression Language (CEL)](https://cloud.google.com/armor/docs/rules-language-reference)

### Format:
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
  redirect_target    = null
  rate_limit_options = {}
  header_action      = []
}
```

### Sample:

```
custom_rules = {

  allow_specific_regions = {
    action             = "allow"
    priority           = 21
    description        = "Allow specific Regions"
    preview            = true
    expression         = <<-EOT
      '[US,AU,BE]'.contains(origin.region_code)
    EOT
  }

  deny_xss_level4_with_exclude = {
    action      = "deny(502)"
    priority    = 100
    description = "test preconfigured policy with Sensitivity level and opt out policies"
    preview     = true
    expression  = <<-EOT
      evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 4, 'opt_out_rule_ids': ['owasp-crs-v030301-id942350-sqli', 'owasp-crs-v030301-id942360-sqli']})
    EOT
  }

}
```

## threat_intelligence_rules:
Add Rules based on [threat intelligence](https://cloud.google.com/armor/docs/threat-intelligence). [Managed protection plus](https://cloud.google.com/armor/docs/managed-protection-overview) subscription is needed to use this feature.

### Format:
Each rule is key value pair where key is a unique name of the rule and value is the action associated with it.

```
threat_intelligence_rules = {
  deny_crawlers_ip = {
    action             = "deny(502)"
    priority           = 31
    description        = "Deny IP addresses of search engine crawlers"
    preview            = false
    feed               = "iplist-search-engines-crawlers"
    redirect_type      = null
    redirect_target    = null
    rate_limit_options = {}
    header_action      = []
  }
}
```

### Sample:

```
threat_intelligence_rules = {

  deny_malicious_ips = {
    action             = "deny(502)"
    priority           = 31
    description        = "Deny IP addresses known to attack web applications"
    preview            = true
    feed               = "iplist-known-malicious-ips"
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
- recaptchaenterprise.keys.list
- recaptchaenterprise.keys.get

Following roles contain above mentioned permissions. You can either assing one of the following role or create custom roles with above permissions.

- Compute Organization Security Policy Admin: `roles/compute.orgSecurityPolicyAdmin`
- Compute Security Admin: `roles/compute.securityAdmin`
- reCAPTCHA Enterprise Admin: `roles/recaptchaenterprise.admin`

### Enable API's
In order to operate with the Service Account you must activate the following API on the project where the Service Account was created:

- Compute Engine API - compute.googleapis.com

## Contributing

Refer to the [contribution guidelines](./CONTRIBUTING.md) for
information on contributing to this module.

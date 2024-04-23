/**
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

locals {
  primary_region   = "us-central1"
  secondary_region = "us-east1"
}

resource "random_id" "suffix" {
  byte_length = 4
}
module "cloud_armor" {
  source  = "GoogleCloudPlatform/cloud-armor/google"
  version = "~> 2.0"

  project_id                           = var.project_id
  name                                 = "test-casp-policy-${random_id.suffix.hex}"
  description                          = "Test Cloud Armor security policy with preconfigured rules, security rules and custom rules"
  default_rule_action                  = "deny(502)"
  type                                 = "CLOUD_ARMOR"
  layer_7_ddos_defense_enable          = true
  layer_7_ddos_defense_rule_visibility = "STANDARD"
  user_ip_request_headers              = ["True-Client-IP", ]

  security_rules = {
    "allow_whitelisted_ip_ranges" = {
      action        = "allow"
      priority      = 11
      description   = "Allow whitelisted IP address ranges"
      src_ip_ranges = ["190.210.69.12", ]
      preview       = false
    }

    "redirect_project_drop" = {
      action        = "redirect"
      priority      = 12
      description   = "Redirect IP address from project drop"
      src_ip_ranges = ["190.217.68.212", "45.116.227.69", ]
      redirect_type = "GOOGLE_RECAPTCHA"
    }

    "rate_ban_project_dropthirty" = {
      action        = "rate_based_ban"
      priority      = 13
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
      priority      = 14
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

}

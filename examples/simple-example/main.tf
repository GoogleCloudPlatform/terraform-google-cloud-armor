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

resource "google_recaptcha_enterprise_key" "primary" {
  display_name = "display-name"

  labels = {
    label-one = "value-one"
  }

  project = var.project_id

  web_settings {
    integration_type  = "INVISIBLE"
    allow_all_domains = true
    allowed_domains   = ["localhost"]
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

module "cloud_armor" {
  source = "../../"

  project_id                           = var.project_id
  name                                 = "test-casp-policy-${random_id.suffix.hex}"
  description                          = "Test Cloud Armor security policy with preconfigured rules, security rules and custom rules"
  default_rule_action                  = "allow"
  type                                 = "CLOUD_ARMOR"
  layer_7_ddos_defense_enable          = true
  layer_7_ddos_defense_rule_visibility = "STANDARD"
  recaptcha_redirect_site_key          = google_recaptcha_enterprise_key.primary.name
  json_parsing                         = "STANDARD"
  log_level                            = "VERBOSE"

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

    "deny_project_honeypot" = {
      action        = "deny(502)"
      priority      = 11
      description   = "Deny Malicious IP address from project honeypot"
      src_ip_ranges = ["190.217.68.211/32", "45.116.227.68/32", "103.43.141.122/32", "123.11.215.36", "123.11.215.37", ]
      preview       = true
    }

    "redirect_project_rd" = {
      action          = "redirect"
      priority        = 12
      description     = "Redirect IP address from project RD"
      src_ip_ranges   = ["190.217.68.215", "45.116.227.99", ]
      redirect_type   = "EXTERNAL_302"
      redirect_target = "https://www.example.com"
    }

    "rate_ban_project_dropten" = {
      action        = "rate_based_ban"
      priority      = 13
      description   = "Rate based ban for address from project dropten as soon as they cross rate limit threshold"
      src_ip_ranges = ["190.217.68.213/32", "45.116.227.70", ]

      rate_limit_options = {
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
        ban_duration_sec                     = 120
        enforce_on_key                       = "ALL"
      }

    }

    "rate_ban_project_dropthirty" = {
      action        = "rate_based_ban"
      priority      = 14
      description   = "Rate based ban for address from project dropthirty only if they cross banned threshold"
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

    deny_specific_regions = {
      action      = "deny(502)"
      priority    = 21
      description = "Deny specific Regions"

      expression = <<-EOT
        '[AU,BE]'.contains(origin.region_code)
      EOT

    }

    deny_specific_ip = {
      action      = "deny(502)"
      priority    = 22
      description = "Deny Specific IP address"

      expression = <<-EOT
        inIpRange(origin.ip, '47.185.201.155/32')
      EOT

    }

    throttle_specific_ip = {
      action      = "throttle"
      priority    = 23
      description = "Throttle specific IP address in US Region"

      expression = <<-EOT
        origin.region_code == "US" && inIpRange(origin.ip, '47.185.201.159/32')
      EOT

      rate_limit_options = {
        exceed_action                        = "deny(502)"
        rate_limit_http_request_count        = 10
        rate_limit_http_request_interval_sec = 60
      }

    }

    rate_ban_specific_ip = {
      action   = "rate_based_ban"
      priority = 24

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

      expression = <<-EOT
        evaluatePreconfiguredWaf('java-v33-stable', {'sensitivity': 3, 'opt_out_rule_ids': ['owasp-crs-v030301-id944240-java', 'owasp-crs-v030301-id944120-java']})
      EOT

    }

  }

}

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

variable "project_id" {
  description = "The project in which the resource belongs."
  type        = string
}

variable "name" {
  description = "Name of the security policy."
  type        = string
}

variable "description" {
  description = "An optional description of this security policy. Max size is 2048."
  type        = string
  default     = null
}

variable "default_rule_action" {
  description = "default rule that allows/denies all traffic with the lowest priority (2,147,483,647)."
  type        = string
  default     = "allow"
}

variable "recaptcha_redirect_site_key" {
  description = "reCAPTCHA site key to be used for all the rules using the redirect action with the redirect type of GOOGLE_RECAPTCHA."
  type        = string
  default     = null
}

variable "pre_configured_rules" {
  description = "Map of pre-configured rules with Sensitivity levels."
  type = map(object({
    action                  = string
    priority                = number
    description             = optional(string)
    preview                 = optional(bool, false)
    redirect_type           = optional(string, null)
    redirect_target         = optional(string, null)
    target_rule_set         = string
    sensitivity_level       = optional(number, 4)
    include_target_rule_ids = optional(list(string), [])
    exclude_target_rule_ids = optional(list(string), [])
    rate_limit_options = optional(object({
      enforce_on_key      = optional(string)
      enforce_on_key_name = optional(string)
      enforce_on_key_configs = optional(list(object({
        enforce_on_key_name = optional(string)
        enforce_on_key_type = optional(string)
      })))
      exceed_action                        = optional(string)
      rate_limit_http_request_count        = optional(number)
      rate_limit_http_request_interval_sec = optional(number)
      ban_duration_sec                     = optional(number)
      ban_http_request_count               = optional(number)
      ban_http_request_interval_sec        = optional(number)
    }), {})

    header_action = optional(list(object({
      header_name  = optional(string)
      header_value = optional(string)
    })), [])

    preconfigured_waf_config_exclusions = optional(map(object({
      target_rule_set = string
      target_rule_ids = optional(list(string), [])
      request_header = optional(list(object({
        operator = string
        value    = optional(string)
      })))
      request_cookie = optional(list(object({
        operator = string
        value    = optional(string)
      })))
      request_uri = optional(list(object({
        operator = string
        value    = optional(string)
      })))
      request_query_param = optional(list(object({
        operator = string
        value    = optional(string)
      })))
    })), null)

  }))

  default = {}
}

variable "security_rules" {
  description = "Map of Security rules with list of IP addresses to block or unblock."
  type = map(object({
    action          = string
    priority        = number
    description     = optional(string)
    preview         = optional(bool, false)
    redirect_type   = optional(string, null)
    redirect_target = optional(string, null)
    src_ip_ranges   = list(string)
    rate_limit_options = optional(object({
      enforce_on_key      = optional(string)
      enforce_on_key_name = optional(string)
      enforce_on_key_configs = optional(list(object({
        enforce_on_key_name = optional(string)
        enforce_on_key_type = optional(string)
      })))
      exceed_action                        = optional(string)
      rate_limit_http_request_count        = optional(number)
      rate_limit_http_request_interval_sec = optional(number)
      ban_duration_sec                     = optional(number)
      ban_http_request_count               = optional(number)
      ban_http_request_interval_sec        = optional(number)
    }), {})
    header_action = optional(list(object({
      header_name  = optional(string)
      header_value = optional(string)
    })), [])
  }))

  default = {}
}

variable "custom_rules" {
  description = "Custom security rules"
  type = map(object({
    action                            = string
    priority                          = number
    description                       = optional(string)
    preview                           = optional(bool, false)
    expression                        = string
    recaptcha_action_token_site_keys  = optional(list(string))
    recaptcha_session_token_site_keys = optional(list(string))
    redirect_type                     = optional(string, null)
    redirect_target                   = optional(string, null)
    rate_limit_options = optional(object({
      enforce_on_key      = optional(string)
      enforce_on_key_name = optional(string)
      enforce_on_key_configs = optional(list(object({
        enforce_on_key_name = optional(string)
        enforce_on_key_type = optional(string)
      })))
      exceed_action                        = optional(string)
      rate_limit_http_request_count        = optional(number)
      rate_limit_http_request_interval_sec = optional(number)
      ban_duration_sec                     = optional(number)
      ban_http_request_count               = optional(number)
      ban_http_request_interval_sec        = optional(number)
      }),
    {})
    header_action = optional(list(object({
      header_name  = optional(string)
      header_value = optional(string)
    })), [])

    preconfigured_waf_config_exclusions = optional(map(object({
      target_rule_set = string
      target_rule_ids = optional(list(string), [])
      request_header = optional(list(object({
        operator = string
        value    = optional(string)
      })))
      request_cookie = optional(list(object({
        operator = string
        value    = optional(string)
      })))
      request_uri = optional(list(object({
        operator = string
        value    = optional(string)
      })))
      request_query_param = optional(list(object({
        operator = string
        value    = optional(string)
      })))
    })), null)

  }))
  default = {}
}

variable "threat_intelligence_rules" {
  description = "Map of Threat Intelligence Feed rules"
  type = map(object({
    action      = string
    priority    = number
    description = optional(string)
    preview     = optional(bool, false)
    feed        = string
    exclude_ip  = optional(string)
    rate_limit_options = optional(object({
      enforce_on_key      = optional(string)
      enforce_on_key_name = optional(string)
      enforce_on_key_configs = optional(list(object({
        enforce_on_key_name = optional(string)
        enforce_on_key_type = optional(string)
      })))
      exceed_action                        = optional(string)
      rate_limit_http_request_count        = optional(number)
      rate_limit_http_request_interval_sec = optional(number)
      ban_duration_sec                     = optional(number)
      ban_http_request_count               = optional(number)
      ban_http_request_interval_sec        = optional(number)
    }), {})
    header_action = optional(list(object({
      header_name  = optional(string)
      header_value = optional(string)
    })), [])
  }))
  default = {}
}

variable "type" {
  description = "Type indicates the intended use of the security policy. Possible values are CLOUD_ARMOR and CLOUD_ARMOR_EDGE."
  type        = string
  default     = "CLOUD_ARMOR"
}

variable "layer_7_ddos_defense_enable" {
  description = "(Optional) If set to true, enables Cloud Armor Adaptive Protection for L7 DDoS detection. Cloud Armor Adaptive Protection is only supported in Global Security Policies of type CLOUD_ARMOR. Set this variable `true` for Adaptive Protection Auto Deploy."
  type        = bool
  default     = false
}

variable "layer_7_ddos_defense_rule_visibility" {
  description = "(Optional) Rule visibility can be one of the following: STANDARD - opaque rules. PREMIUM - transparent rules. This field is only supported in Global Security Policies of type CLOUD_ARMOR."
  type        = string
  default     = "STANDARD"
}

variable "layer_7_ddos_defense_threshold_configs" {
  description = "(Optional) Configuration options for layer7 adaptive protection for various customizable thresholds. `adaptive_protection_auto_deploy.load_threshold`, `adaptive_protection_auto_deploy.confidence_threshold`, `adaptive_protection_auto_deploy.expiration_sec`, `adaptive_protection_auto_deploy.impacted_baseline_threshold` cannot be provided if `layer_7_ddos_defense_threshold_configs` is not null"
  type = list(object({
    name                                    = string
    auto_deploy_load_threshold              = optional(number)
    auto_deploy_confidence_threshold        = optional(number)
    auto_deploy_impacted_baseline_threshold = optional(number)
    auto_deploy_expiration_sec              = optional(number)
    detection_load_threshold                = optional(number)
    detection_absolute_qps                  = optional(number)
    detection_relative_to_baseline_qps      = optional(number)
    traffic_granularity_configs = optional(list(object({
      type                     = string
      value                    = optional(string)
      enable_each_unique_value = optional(bool)
    })))
  }))
  default = null
}

variable "adaptive_protection_auto_deploy" {
  description = "Configuration for Automatically deploy Cloud Armor Adaptive Protection suggested rules. `priority` and `action` fields are required if `enable` is set to true. Requires `layer_7_ddos_defense_enable` set to `true`. `load_threshold`, `confidence_threshold`, `expiration_sec`, `impacted_baseline_threshold` cannot be provided if `layer_7_ddos_defense_threshold_configs` is not null. `exceed_redirect_options` can be provided only if `rate_limit_options.exceed_action` is `redirect`"
  type = object({
    enable      = bool
    priority    = optional(number, null)
    action      = optional(string, null)
    preview     = optional(bool, false)
    description = optional(string, "Adaptive Protection auto-deploy")

    load_threshold              = optional(number)
    confidence_threshold        = optional(number)
    impacted_baseline_threshold = optional(number)
    expiration_sec              = optional(number)

    redirect_type   = optional(string)
    redirect_target = optional(string)

    rate_limit_options = optional(object({
      enforce_on_key      = optional(string)
      enforce_on_key_name = optional(string)

      enforce_on_key_configs = optional(list(object({
        enforce_on_key_name = optional(string)
        enforce_on_key_type = optional(string)
      })))

      exceed_action                        = optional(string)
      rate_limit_http_request_count        = optional(number)
      rate_limit_http_request_interval_sec = optional(number)
      ban_duration_sec                     = optional(number)
      ban_http_request_count               = optional(number)
      ban_http_request_interval_sec        = optional(number)
      exceed_redirect_options = optional(object({
        type   = string
        target = optional(string)
      }))
    }), {})
  })

  default = {
    enable = false
  }
}

variable "json_parsing" {
  description = "Whether or not to JSON parse the payload body. Possible values are DISABLED and STANDARD. Not supported for CLOUD_ARMOR_EDGE policy type."
  type        = string
  default     = "DISABLED"
}

variable "log_level" {
  description = "Log level to use. Possible values are NORMAL and VERBOSE. Not supported for CLOUD_ARMOR_EDGE policy type."
  type        = string
  default     = "NORMAL"
}

variable "json_custom_config_content_types" {
  description = "A list of custom Content-Type header values to apply the JSON parsing. Only applicable when json_parsing is set to STANDARD. Not supported for CLOUD_ARMOR_EDGE policy type."
  type        = list(string)
  default     = []
}

variable "user_ip_request_headers" {
  description = "An optional list of case-insensitive request header names to use for resolving the callers client IP address."
  type        = list(string)
  default     = []
}

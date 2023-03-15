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
  description = "The project in which the resource belongs"
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
  description = "default rule that allows/denies all traffic with the lowest priority (2,147,483,647)"
  type        = string
  default     = "allow"
}

variable "recaptcha_redirect_site_key" {
  description = "reCAPTCHA site key to be used for all the rules using the redirect action with the redirect type of GOOGLE_RECAPTCHA"
  type        = string
  default     = null
}

variable "pre_configured_rules" {
  description = "Map of pre-configured rules Sensitivity levels"
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
      enforce_on_key                       = optional(string)
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
  }))
  default = {}
}

variable "security_rules" {
  description = "Map of Security rules with list of IP addresses to block or unblock"
  type = map(object({
    action          = string
    priority        = number
    description     = optional(string)
    preview         = optional(bool, false)
    redirect_type   = optional(string, null)
    redirect_target = optional(string, null)
    src_ip_ranges   = list(string)
    rate_limit_options = optional(object({
      enforce_on_key                       = optional(string)
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
  }))
  default = {}
}

variable "custom_rules" {
  description = "Custome security rules"
  type = map(object({
    action          = string
    priority        = number
    description     = optional(string)
    preview         = optional(bool, false)
    expression      = string
    redirect_type   = optional(string, null)
    redirect_target = optional(string, null)
    rate_limit_options = optional(object({
      enforce_on_key                       = optional(string)
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
  }))
  default = {}
}

variable "threat_intelligence_rules" {
  description = "Map of Threat Intelligence Feed rules"
  type        = map(any)
  default     = {}
}

variable "type" {
  description = "Type indicates the intended use of the security policy. Possible values are CLOUD_ARMOR and CLOUD_ARMOR_EDGE"
  type        = string
  default     = "CLOUD_ARMOR"
}

variable "layer_7_ddos_defense_enable" {
  description = "(Optional) If set to true, enables CAAP for L7 DDoS detection"
  type        = bool
  default     = false
}

variable "layer_7_ddos_defense_rule_visibility" {
  description = "(Optional) Rule visibility can be one of the following: STANDARD - opaque rules. PREMIUM - transparent rules"
  type        = string
  default     = "STANDARD"
}

variable "json_parsing" {
  description = "Whether or not to JSON parse the payload body. Possible values are DISABLED and STANDARD. Defaults to DISABLED"
  type        = string
  default     = "DISABLED"
}

variable "log_level" {
  description = "Log level to use. Possible values are NORMAL and VERBOSE. Defaults to NORMAL"
  type        = string
  default     = "NORMAL"
}

variable "json_custom_config_content_types" {
  description = "A list of custom Content-Type header values to apply the JSON parsing. Only applicable when json_parsing is set to STANDARD"
  type        = list(string)
  default     = []
}

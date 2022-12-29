/**
 * Copyright 2022 Google LLC
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
  description = "(Required) The name of the security policy."
  type        = string
}

variable "description" {
  description = "(Optional) An optional description of this security policy. Max size is 2048."
  type        = string
  default     = null
}

variable "default_rule_action" {
  description = "default rule that allows/denies all traffic with the lowest priority (2,147,483,647)"
  type        = string
  default     = "deny(403)"
}

variable "pre_configured_rules" {
  description = "Map of pre-configured rules Sensitivity levels"
  type        = map(any)
  default     = {}
}

variable "security_rules" {
  description = "Map of Security rules with list of IP addresses to block or unblock"
  type        = map(any)
  default     = {}
}

variable "custom_rules" {
  description = "Custome security rules"
  type        = map(any)
  default     = {}
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

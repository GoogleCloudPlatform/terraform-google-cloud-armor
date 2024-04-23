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

variable "regions" {
  description = "The regions in which enable advanced network DDoS protection"
  type        = list(string)
}

variable "ddos_protection_config" {
  description = "Configuration for Google Cloud Armor DDOS Proctection Config. 1) ADVANCED: additional protections for Managed Protection Plus subscribers 2) ADVANCED_PREVIEW: flag to enable the security policy in preview mode"
  type        = string
  default     = "ADVANCED"
}

variable "policy_name" {
  description = "Name of the advanced network ddos protection security policy. Name must be 1-63 characters long and match the regular expression a-z? which means the first character must be a lowercase letter, and all following characters must be a dash, lowercase letter, or digit, except the last character, which cannot be a dash"
  type        = string
  default     = "adv-network-ddos-protection"
}

variable "policy_description" {
  description = "An optional description of advanced network ddos protection security policy"
  type        = string
  default     = "CA Advance DDoS protection"
}

variable "network_edge_security_service_name" {
  description = "Name of network edge security service resource for advanced network ddos protection"
  type        = string
  default     = "adv-network-ddos-protection"
}

variable "network_edge_security_service_description" {
  description = "description of edge security service for advanced network ddos protection"
  type        = string
  default     = "edge security service for advanced network ddos protection"
}

/**
 * Copyright 2024 Google LLC
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

variable "region" {
  description = "The region in which enablesecurity policy is created"
  type        = string
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

variable "policy_user_defined_fields" {
  description = "Definitions of user-defined fields for CLOUD_ARMOR_NETWORK policies. A user-defined field consists of up to 4 bytes extracted from a fixed offset in the packet, relative to the IPv4, IPv6, TCP, or UDP header, with an optional mask to select certain bits"
  type = list(object({
    name   = optional(string)
    base   = string
    offset = optional(number)
    size   = optional(number)
    mask   = optional(string)
  }))
  default = null
}

variable "policy_rules" {
  description = "Policy Rules"
  type = list(object({
    priority         = number
    action           = string
    preview          = optional(bool)
    description      = optional(string)
    ip_protocols     = optional(list(string))
    src_ip_ranges    = optional(list(string))
    src_asns         = optional(list(string))
    src_region_codes = optional(list(string))
    src_ports        = optional(list(string))
    dest_ports       = optional(list(string))
    dest_ip_ranges   = optional(list(string))

    user_defined_fields = optional(list(object({
      name   = optional(string)
      values = optional(list(string))
    })))
  }))
  default = null
}

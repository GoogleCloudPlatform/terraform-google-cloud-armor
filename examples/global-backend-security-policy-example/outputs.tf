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

output "security_policy" {
  value       = module.cloud_armor.policy
  description = "Cloud Armor security policy created"
}

output "policy_name" {
  value       = module.cloud_armor.policy.name
  description = "Security Policy name"
}

output "address_group_name" {
  value = google_network_security_address_group.address_group.name
}

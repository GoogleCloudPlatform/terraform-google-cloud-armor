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

output "adv_ddos_protection_policies" {
  value       = module.advanced_network_ddos_protection.adv_ddos_protection_policies
  description = "Advanced Network DDoS protection Security policies created"
}

output "network_edge_security_services" {
  value       = module.advanced_network_ddos_protection.network_edge_security_services
  description = "Network edge security services created"
}

output "security_policy" {
  value       = module.network_edge_security_policy.security_policy
  description = "Regional Network Security policy created"
}

output "policy_rules" {
  value       = module.network_edge_security_policy.policy_rules
  description = "Security policy rules created"
}

output "test_nlb_url" {
  value       = "curl http://${google_compute_forwarding_rule.default.ip_address}"
  description = "Use this command to test access to the load balancer. Try it from the IP address provided in whitelisted_ingress_ip_ranges and a different IP address"
}

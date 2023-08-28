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
  display_name = "test-recaptcha-key"

  labels = {
    purpose = "testing"
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
  name                                 = "test-policy-recaptcha-${random_id.suffix.hex}"
  description                          = "Test Cloud Armor security policy with preconfigured rules, security rules and custom rules"
  default_rule_action                  = "allow"
  type                                 = "CLOUD_ARMOR"
  layer_7_ddos_defense_enable          = true
  layer_7_ddos_defense_rule_visibility = "STANDARD"
  recaptcha_redirect_site_key          = google_recaptcha_enterprise_key.primary.name
}

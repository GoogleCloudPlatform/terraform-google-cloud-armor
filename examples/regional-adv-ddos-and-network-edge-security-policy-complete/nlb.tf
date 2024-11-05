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

############## Health Check ####################
resource "google_compute_region_health_check" "default" {
  name    = "ca-http-region-health-check"
  project = var.project_id
  region  = local.primary_region

  timeout_sec        = 1
  check_interval_sec = 1

  http_health_check {
    port = "80"
  }
  log_config {
    enable = true
  }
}

############ Backend service on the instance group ###################

resource "google_compute_region_backend_service" "backend" {
  provider              = google-beta
  project               = var.project_id
  name                  = "ca-website-backend-svc"
  region                = local.primary_region
  load_balancing_scheme = "EXTERNAL"
  health_checks         = [google_compute_region_health_check.default.id]
  backend {
    group          = google_compute_instance_group.ca_vm_1_ig.self_link
    balancing_mode = "CONNECTION"
  }

  log_config {
    enable      = true
    sample_rate = 0.5
  }
  ## Attach Cloud Armor policy to the backend service
  security_policy = module.network_edge_security_policy.security_policy.self_link
}

############## Forwarding rule ####################

resource "google_compute_forwarding_rule" "default" {
  provider        = google-beta
  project         = var.project_id
  name            = "ca-website-forwarding-rule"
  region          = local.primary_region
  port_range      = 80
  backend_service = google_compute_region_backend_service.backend.id
}

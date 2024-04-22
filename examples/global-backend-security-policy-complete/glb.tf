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

# # ############## Healthcheck

resource "google_compute_http_health_check" "default" {
  provider = google-beta
  project  = var.project_id

  name               = "glb-ca-health-check"
  check_interval_sec = 5
  timeout_sec        = 3
}

resource "google_compute_backend_service" "backend_service" {
  provider = google-beta

  project = var.project_id

  name        = "glb-ca-web-backend-svc-a"
  port_name   = "http"
  protocol    = "HTTP"
  timeout_sec = 10

  backend {
    group           = google_compute_instance_group.ca_vm_1_ig.self_link
    max_utilization = 0.5
  }

  health_checks         = [google_compute_http_health_check.default.id]
  load_balancing_scheme = "EXTERNAL"

  ## Attach Cloud Armor policy to the backend service
  security_policy = module.cloud_armor.policy.self_link
}

resource "google_compute_url_map" "default" {
  provider = google-beta

  project     = var.project_id
  name        = "glb-ca-https"
  description = "global ca url map"

  default_service = google_compute_backend_service.backend_service.id
}

resource "google_compute_target_http_proxy" "http_glb_proxy" {
  name    = "glb-ca-http-proxy"
  url_map = google_compute_url_map.default.id
  project = var.project_id
}

resource "google_compute_global_address" "glb_external_address" {
  name    = "glb-ca-http-global-ip"
  project = var.project_id
}


resource "google_compute_global_forwarding_rule" "glb_forwarding_rule" {
  name       = "glb-ca-http-global-fr"
  target     = google_compute_target_http_proxy.http_glb_proxy.self_link
  ip_address = google_compute_global_address.glb_external_address.address
  port_range = "80"
  project    = var.project_id
}

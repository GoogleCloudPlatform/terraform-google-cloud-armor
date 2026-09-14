# Upgrading to v9.0.0

The v9.0 release contains backwards-incompatible changes.

### Rate limit `enforce_on_key_configs` allows a key type to repeat

`enforce_on_key_configs` entries are rendered in the order they are listed in the configuration. They were previously sorted by `enforce_on_key_type`, which also made a rule fail to plan with `Duplicate object key` when a key type appeared more than once.

Cloud Armor allows up to three rate limit keys per rule and allows `HTTP_HEADER` and `HTTP_COOKIE` to repeat, so configurations like this one are now accepted:

```tf
"throttle_by_client" = {
  action        = "throttle"
  priority      = 15
  src_ip_ranges = ["190.217.68.214"]

  rate_limit_options = {
    exceed_action                        = "deny(502)"
    rate_limit_http_request_count        = 10
    rate_limit_http_request_interval_sec = 60

    enforce_on_key_configs = [
      {
        enforce_on_key_type = "HTTP_COOKIE"
        enforce_on_key_name = "site_id"
      },
+     {
+       enforce_on_key_type = "HTTP_HEADER"
+       enforce_on_key_name = "x-api-key"
+     },
+     {
+       enforce_on_key_type = "HTTP_HEADER"
+       enforce_on_key_name = "x-client-id"
+     }
    ]
  }
}
```

#### Upgrade impact

No configuration changes are required, and the rate limit keys themselves are unchanged.

A rule whose `enforce_on_key_configs` are not already listed in `enforce_on_key_type` order plans a one-time in-place update that reorders the blocks. For example, a rule listing `HTTP_PATH` before `HTTP_COOKIE` holds them in the opposite order in state on v8.x, and v9.0 rewrites the rule to match the configured order:

```
  # module.cloud_armor.google_compute_security_policy.policy will be updated in-place
  ~ resource "google_compute_security_policy" "policy" {
      ~ rule {
          ~ rate_limit_options {
              - enforce_on_key_configs {
                  - enforce_on_key_name = "site_id" -> null
                  - enforce_on_key_type = "HTTP_COOKIE" -> null
                }
              + enforce_on_key_configs {
                  + enforce_on_key_type = "HTTP_PATH"
                }
```

To avoid the update, list the entries in `enforce_on_key_type` order.

# Upgrading to v10.0.0

The v10.0 release contains backwards-incompatible changes.

### Default policy names and descriptions updated in submodules

The default values for policy name and description variables in the `regional-backend-security-policy` and `network-edge-security-policy` submodules previously contained copy-pasted defaults (`"adv-network-ddos-protection"` and `"CA Advance DDoS protection"`). These defaults have been updated to match each submodule's purpose:

| Submodule | Variable | Previous Default | New Default |
| :--- | :--- | :--- | :--- |
| `regional-backend-security-policy` | `name` | `"adv-network-ddos-protection"` | `"regional-backend-security-policy"` |
| `regional-backend-security-policy` | `description` | `"CA Advance DDoS protection"` | `"Regional backend security policy"` |
| `network-edge-security-policy` | `policy_name` | `"adv-network-ddos-protection"` | `"network-edge-security-policy"` |
| `network-edge-security-policy` | `policy_description` | `"CA Advance DDoS protection"` | `"Network edge security policy"` |

#### Upgrade impact

If your configuration explicitly sets `name`/`policy_name` and `description`/`policy_description`, no action is required.

If your configuration omitted these variables and relied on the previous default values, upgrading to v10.0 will cause Terraform to plan a **force replacement (destroy and recreate)** of the `google_compute_region_security_policy` resource due to the policy name change. To avoid recreating existing policies, explicitly set the previous default values in your module block before upgrading:

```tf
module "regional_backend_security_policy" {
  source  = "GoogleCloudPlatform/cloud-armor/google//modules/regional-backend-security-policy"
  version = "~> 10.0"

+ name        = "adv-network-ddos-protection"
+ description = "CA Advance DDoS protection"
  ...
}
```

---

### `header_action` attributes `header_name` and `header_value` are now required

In the root module, the `header_action` list of objects inside `pre_configured_rules`, `security_rules`, `custom_rules`, and `threat_intelligence_rules` previously defined `header_name` and `header_value` as `optional(string)`. Both attributes are now strictly required (`string`):

```tf
header_action = optional(list(object({
- header_name  = optional(string)
- header_value = optional(string)
+ header_name  = string
+ header_value = string
})), [])
```

#### Upgrade impact

Any `header_action` entry that omits `header_name` or `header_value` (or sets either to `null`) will now fail Terraform type checking during `terraform plan`. Ensure both `header_name` and `header_value` are provided for every object in `header_action`.

---

### `security_rules` output in `regional-backend-security-policy` submodule includes all rule types

In `modules/regional-backend-security-policy`, the `security_rules` output previously only returned rules created via the `security_rules` input variable (`google_compute_region_security_policy_rule.security_rules`).

It now returns a merged map of all rules created by the submodule across `security_rules`, `custom_rules`, and `pre_configured_rules`:

```tf
output "security_rules" {
  description = "Security policy rules created"
  value = merge(
    google_compute_region_security_policy_rule.security_rules,
    google_compute_region_security_policy_rule.custom_rules,
    google_compute_region_security_policy_rule.pre_configured_rules,
  )
}
```

#### Upgrade impact

Downstream references to `module.<name>.security_rules` will now include keys and resource objects for `custom_rules` and `pre_configured_rules` in addition to `security_rules`.

---

### Stricter input variable validations

Input `validation` blocks have been added across root module and submodule variables:
- **Root module (`variables.tf`)**:
  - `description`: Maximum length of 2048 characters.
  - `default_rule_action`: Must be one of `allow`, `deny(403)`, `deny(404)`, `deny(502)`.
  - `type`: Must be one of `CLOUD_ARMOR`, `CLOUD_ARMOR_EDGE`, `CLOUD_ARMOR_INTERNAL_SERVICE`.
  - `layer_7_ddos_defense_rule_visibility`: Must be either `STANDARD` or `PREMIUM`.
  - `json_parsing`: Must be one of `DISABLED`, `STANDARD`, `STANDARD_WITH_GRAPHQL`.
  - `log_level`: Must be either `NORMAL` or `VERBOSE`.
  - `request_body_inspection_size`: Must be `null` or one of `8KB`, `16KB`, `32KB`, `48KB`, `64KB` (case-insensitive).
- **`advanced-network-ddos-protection` submodule (`variables.tf`)**:
  - `ddos_protection_config`: Must be one of `ADVANCED`, `ADVANCED_PREVIEW`, `STANDARD`.

#### Upgrade impact

Configurations passing invalid values that previously succeeded during `terraform plan` (and failed only during GCP API creation/update) will now fail immediately during `terraform validate` or `terraform plan`.

---

### Internal refactoring of rule blocks and dynamic iterators

- **Root module (`main.tf`)**: Consolidated separate `dynamic "rule"` blocks for `security_rules`, `custom_rules`, `pre_configured_rules`, `threat_intelligence_rules`, and `adaptive_protection_auto_deploy` into a unified `local.all_rules` map and a single `dynamic "rule"` block. The mandatory default rule (`priority = 2147483647`) is now defined as a static `rule` block.
- **Root & Regional submodules**: Replaced synthetic map keys in `dynamic` blocks (such as base64-encoded keys in `preconfigured_waf_config_exclusions` field exclusions and `threshold_configs` / `traffic_granularity_configs`) with direct list iteration.

#### Upgrade impact

No configuration changes are required. Because `rule` blocks in `google_compute_security_policy` are unordered sets in the Terraform provider schema, no policy or rule recreation will occur.

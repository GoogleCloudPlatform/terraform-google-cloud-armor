# Upgrading to v2.0.0

The v2.0 release contains backwards-incompatible changes.

This update requires upgrading the minimum provider version to `4.79`.

### TPG max version is bumped to 5.x.  
In `4.X`, the default value for `rule.rate_limit_options.enforce_on_key` is `ALL`. In `5.X` this field no longer has a default value. If you need `All` you will need to set it explicitly. See [Rule 2](https://github.com/GoogleCloudPlatform/terraform-google-cloud-armor/blob/main/examples/security-policy-all/main.tf) in `examples/security-policy-all` folder for reference.

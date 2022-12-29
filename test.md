### Test
```
gcloud compute security-policies list --format json
```

### output
```
name should be my-test-ca-policy-1
```


### Test

```
gcloud compute security-policies describe my-test-ca-policy-1 --format json
```

### output
```

adaptiveProtectionConfig.layer7DdosDefenseConfig.enable :  true

adaptiveProtectionConfig.layer7DdosDefenseConfig.ruleVisibility : STANDARD

```
### Test
```
gcloud compute security-policies rules describe 1 --security-policy my-test-ca-policy-1 --format json
```

### output
```
  action: deny(502)
  description: "SQL Sensitivity Level 4"
  preview: false
  priority: 1
  match.expr.expression: evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 4})
```

### Test
```
gcloud compute security-policies rules describe 2 --security-policy my-test-ca-policy-1 --format json
```

### output
```
  action: throttle
  description: "XSS Sensitivity Level 2 with excluded rules"
  preview: false
  priority: 2
  match.expr.expression: evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 2, 'opt_out_rule_ids': ['owasp-crs-v030301-id941380-xss','owasp-crs-v030301-id941340-xss']})
  rateLimitOptions.conformAction: allow
  rateLimitOptions.enforceOnKey: ALL
  rateLimitOptions.exceedAction: deny(502)
  rateLimitOptions.rateLimitThreshold.count: 10
  rateLimitOptions.rateLimitThreshold.intervalSec: 60
```


### Test
```
gcloud compute security-policies rules describe 3 --security-policy my-test-ca-policy-1 --format json
```

### output
```
  action: rate_based_ban
  description: "PHP Sensitivity Level 1 with included rules"
  preview: false
  priority: 3
  match.expr.expression: evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 0, 'opt_in_rule_ids': ['owasp-crs-v030301-id933190-php','owasp-crs-v030301-id933111-php']})
  rateLimitOptions.conformAction: allow
  rateLimitOptions.enforceOnKey: ALL
  rateLimitOptions.exceedAction: deny(502)
  rateLimitOptions.banDurationSec: 600
  rateLimitOptions.banThreshold.count: 1000
  rateLimitOptions.banThreshold.intervalSec: 300
  rateLimitOptions.rateLimitThreshold.count: 10
  rateLimitOptions.rateLimitThreshold.intervalSec: 60
```


### Test
```
gcloud compute security-policies rules describe 4 --security-policy my-test-ca-policy-1 --format json
```
### output
```
  action: redirect
  description: "Remote file inclusion 4"
  preview: false
  priority: 4
  match.expr.expression: evaluatePreconfiguredWaf('rfi-v33-stable', {'sensitivity': 4})
  redirectOptions.type : GOOGLE_RECAPTCHA
```

### Test
```
gcloud compute security-policies rules describe 11 --security-policy my-test-ca-policy-1 --format json
```

### output
```
  action: deny(502)
  description: "Deny Malicious IP address from project honeypot"
  preview: false
  priority: 11
  length of match.config.srcIpRanges = 4
  match.versionedExpr : "SRC_IPS_V1"
```

### Test
```
gcloud compute security-policies rules describe 12 --security-policy my-test-ca-policy-1 --format json
```

### output
```
  action: redirect
  description: "Redirect IP address from project drop
  preview: false
  priority: 12
  length of match.config.srcIpRanges = 2
  match.versionedExpr : "SRC_IPS_V1"
  redirectOptions.type : GOOGLE_RECAPTCHA
```


### Test
```
gcloud compute security-policies rules describe 13 --security-policy my-test-ca-policy-1 --format json
```

### output
```
  action: rate_based_ban
  description: "Rate based ban for address from project dropten as soon as they cross rate limit threshold"
  preview: false
  priority: 13
  length of match.config.srcIpRanges = 2
  match.versionedExpr : "SRC_IPS_V1"
  rateLimitOptions.conformAction: allow
  rateLimitOptions.enforceOnKey: ALL
  rateLimitOptions.exceedAction: deny(502)
  rateLimitOptions.banDurationSec: 120
  rateLimitOptions.rateLimitThreshold.count: 10
  rateLimitOptions.rateLimitThreshold.intervalSec: 60
```

### Test
```
gcloud compute security-policies rules describe 14 --security-policy my-test-ca-policy-1 --format json
```

### output
```
  action: rate_based_ban
  description: "Rate based ban for address from project dropthirty only if they cross banned threshold"
  preview: false
  priority: 14
  length of match.config.srcIpRanges = 2
  match.versionedExpr : "SRC_IPS_V1"
  rateLimitOptions.conformAction: allow
  rateLimitOptions.enforceOnKey: ALL
  rateLimitOptions.exceedAction: deny(502)
  rateLimitOptions.banDurationSec: 300
  rateLimitOptions.banThreshold.count: 1000
  rateLimitOptions.banThreshold.intervalSec: 300
  rateLimitOptions.rateLimitThreshold.count: 10
  rateLimitOptions.rateLimitThreshold.intervalSec: 60
```

### Test
```
gcloud compute security-policies rules describe 15 --security-policy my-test-ca-policy-1 --format json
```

### output
```
  action: throttle
  description: "Throttle IP addresses from project droptwenty"
  preview: false
  priority: 15
  length of match.config.srcIpRanges = 2
  match.versionedExpr : "SRC_IPS_V1"
  rateLimitOptions.conformAction: allow
  rateLimitOptions.enforceOnKey: ALL
  rateLimitOptions.exceedAction: deny(502)
  rateLimitOptions.rateLimitThreshold.count: 10
  rateLimitOptions.rateLimitThreshold.intervalSec: 60
```

### Test
```
gcloud compute security-policies rules describe 21 --security-policy my-test-ca-policy-1 --format json
```

### output
```
  action: allow
  description:  "Allow specific Regions"
  preview: false
  priority: 21
  match.expr.expression:  "'[US,AU,BE]'.contains(origin.region_code)\n"
```

### Test
```
gcloud compute security-policies rules describe 22 --security-policy my-test-ca-policy-1 --format json
```

### output
```
  action: "deny(502)"
  description:  "Deny Specific IP address"
  preview: false
  priority: 22
  match.expr.expression: "inIpRange(origin.ip, '47.185.201.155/32')\n"
```

### Test
```
gcloud compute security-policies rules describe 23 --security-policy my-test-ca-policy-1 --format json
```

### output
```
  action: throttle
  description: "Throttle specific IP address in US Region"
  preview: false
  priority: 23
  match.expr.expression:  "origin.region_code == \"US\" && inIpRange(origin.ip, '47.185.201.159/32')\n"
  rateLimitOptions.conformAction: allow
  rateLimitOptions.enforceOnKey: ALL
  rateLimitOptions.exceedAction: deny(502)
  rateLimitOptions.rateLimitThreshold.count: 10
  rateLimitOptions.rateLimitThreshold.intervalSec: 60
```


### Test
```
gcloud compute security-policies rules describe 24 --security-policy my-test-ca-policy-1 --format json
```

### output
```
  action: rate_based_ban
  description: "Rate based ban for specific IP address"
  preview: false
  priority: 24
  match.expr.expression:  "inIpRange(origin.ip, '47.185.201.160/32')\n"
  rateLimitOptions.conformAction: allow
  rateLimitOptions.enforceOnKey: ALL
  rateLimitOptions.exceedAction: deny(502)
  rateLimitOptions.banDurationSec: 120
  rateLimitOptions.banThreshold.count: 1000
  rateLimitOptions.banThreshold.intervalSec: 600
  rateLimitOptions.rateLimitThreshold.count: 10
  rateLimitOptions.rateLimitThreshold.intervalSec: 60
```

### Test
```
gcloud compute security-policies rules describe 100 --security-policy my-test-ca-policy-1 --format json
```

### output
```
  action: "deny(502)"
  description:  "test Sensitivity level policies"
  preview: false
  priority: 100
  match.expr.expression: "expression": "evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 4, 'opt_out_rule_ids': ['owasp-crs-v030301-id942350-sqli', 'owasp-crs-v030301-id942360-sqli']})\n"
```

### Test
```
gcloud compute security-policies rules describe 2147483647 --security-policy my-test-ca-policy-1 --format json
```

### output
```
  action: "deny(502)"
  description:   "Default rule, higher priority overrides it"
  preview: false
  priority: 2147483647
  length of match.config.srcIpRanges = 1
  match.versionedExpr : "SRC_IPS_V1"
```

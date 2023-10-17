// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package security_policy

import (
	"fmt"
	"testing"

	"github.com/GoogleCloudPlatform/cloud-foundation-toolkit/infra/blueprint-test/pkg/gcloud"
	"github.com/GoogleCloudPlatform/cloud-foundation-toolkit/infra/blueprint-test/pkg/tft"
	"github.com/stretchr/testify/assert"
)

func TestSecurityPolicyAll(t *testing.T) {
	casp := tft.NewTFBlueprintTest(t)

	casp.DefineVerify(func(assert *assert.Assertions) {
		casp.DefaultVerify(assert)

		projectId := casp.GetStringOutput("project_id")
		policyName := casp.GetStringOutput("policy_name")

		spName := gcloud.Run(t, fmt.Sprintf("compute security-policies describe %s --project %s", policyName, projectId))
		for _, sp := range spName.Array() {
			pname := sp.Get("name").String()
			assert.Equal(policyName, pname, "has expected name")
		}

		// 	Rule 1
		spRule1 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 1 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range spRule1.Array() {
			assert.Equal("deny(502)", sp.Get("action").String(), "priority 1 rule has expected action")
			assert.Equal("evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 4})", sp.Get("match.expr.expression").String(), "priority 1 rule has expected rule expression")
			assert.Empty(sp.Get("description").String(), "priority 1 rule has expected description")
			assert.False(sp.Get("preview").Bool(), "priority 1 rule Preview is set to False")
		}

		// 	Rule 2
		spRule2 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 2 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range spRule2.Array() {
			assert.True(sp.Get("preview").Bool(), "priority 2 rule Preview is set to True")
			assert.Equal("throttle", sp.Get("action").String(), "priority 2 rule has expected action")
			assert.Equal("XSS Sensitivity Level 2 with excluded rules", sp.Get("description").String(), "priority 2 rule has expected description")
			assert.Equal("allow", sp.Get("rateLimitOptions.conformAction").String(), "priority 2 rule has expected Rate limit confirm action")
			assert.Equal("", sp.Get("rateLimitOptions.enforceOnKey").String(), "priority 2 rule has expected Rate limit enforce on key")
			assert.Equal("deny(502)", sp.Get("rateLimitOptions.exceedAction").String(), "priority 2 rule has expected Rate limit exceed action")
			assert.Equal("10", sp.Get("rateLimitOptions.rateLimitThreshold.count").String(), "priority 2 rule has expected Rate limit threshold count")
			assert.Equal("60", sp.Get("rateLimitOptions.rateLimitThreshold.intervalSec").String(), "priority 2 rule has expected Rate limit threshold interval")
		}

		// 	Rule 3
		spRule3 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 3 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range spRule3.Array() {
			assert.False(sp.Get("preview").Bool(), " priority 3 rule Preview is set to False")
			assert.Equal("rate_based_ban", sp.Get("action").String(), "priority 3 rule has expected action")
			assert.Equal("PHP Sensitivity Level 1 with included rules", sp.Get("description").String(), "priority 3 rule has expected description")
			assert.Equal("allow", sp.Get("rateLimitOptions.conformAction").String(), "priority 3 rule has expected Rate limit confirm action")
			assert.Equal("ALL", sp.Get("rateLimitOptions.enforceOnKey").String(), "priority 3 rule has expected Rate limit enforce on key")
			assert.Equal("deny(502)", sp.Get("rateLimitOptions.exceedAction").String(), "priority 3 rule has expected Rate limit exceed action")
			assert.Equal("10", sp.Get("rateLimitOptions.rateLimitThreshold.count").String(), "priority 3 rule has expected Rate limit threshold count")
			assert.Equal("60", sp.Get("rateLimitOptions.rateLimitThreshold.intervalSec").String(), "priority 3 rule has expected Rate limit threshold interval")
			assert.Equal("600", sp.Get("rateLimitOptions.banDurationSec").String(), "priority 3 rule has expected Rate limit ban duration")
			assert.Equal("1000", sp.Get("rateLimitOptions.banThreshold.count").String(), "priority 3 rule has expected Rate limit ban threshold count")
			assert.Equal("300", sp.Get("rateLimitOptions.banThreshold.intervalSec").String(), "priority 3 rule has expected Rate limit ban threshold interval")
		}

		// 	Rule 4
		spRule4 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 4 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range spRule4.Array() {
			assert.False(sp.Get("preview").Bool(), "priority 4 rule Preview is set to False")
			assert.Equal("redirect", sp.Get("action").String(), "priority 4 rule has expected action")
			assert.Equal("Remote file inclusion 4", sp.Get("description").String(), "priority 4 rule has expected description")
			assert.Equal("evaluatePreconfiguredWaf('rfi-v33-stable', {'sensitivity': 4})", sp.Get("match.expr.expression").String(), "priority 1 rule has expected rule expression")
			assert.Equal("GOOGLE_RECAPTCHA", sp.Get("redirectOptions.type").String(), "priority 4 rule has expected redirect type")
		}

		// 	Rule 11
		spRule11 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 11 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range spRule11.Array() {
			assert.True(sp.Get("preview").Bool(), "priority 11 rule Preview is set to True")
			assert.Equal("deny(502)", sp.Get("action").String(), "priority 11 rule has expected action")
			assert.Equal("Deny Malicious IP address from project honeypot", sp.Get("description").String(), "priority 11 rule has expected description")
			assert.Equal("SRC_IPS_V1", sp.Get("match.versionedExpr").String(), "priority 11 rule has expected redirect type")

			srcIpRanges := sp.Get("match.config.srcIpRanges").Array()
			assert.Equal(2, len(srcIpRanges), "found only 2 IP address")
			assert.Equal(srcIpRanges[0].String(), "190.217.68.211", "priority 11 rule found first valid cidr range")
			assert.Equal(srcIpRanges[1].String(), "45.116.227.68", "priority 11 rule found second valid cidr range")
		}

		// 	Rule 12
		spRule12 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 12 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range spRule12.Array() {
			assert.False(sp.Get("preview").Bool(), "priority 12 rule Preview is set to False")
			assert.Equal("redirect", sp.Get("action").String(), "priority 12 rule has expected action")
			assert.Equal("Redirect IP address from project drop", sp.Get("description").String(), "priority 12 rule has expected description")
			assert.Equal("SRC_IPS_V1", sp.Get("match.versionedExpr").String(), "priority 12 rule has expected redirect type")

			srcIpRanges := sp.Get("match.config.srcIpRanges").Array()
			assert.Equal(2, len(srcIpRanges), "priority 12 rule found only 2 IP address")
			assert.Equal(srcIpRanges[0].String(), "190.217.68.212", "priority 12 rule found first valid cidr range")
			assert.Equal(srcIpRanges[1].String(), "45.116.227.69", "priority 12 rule found second valid cidr range")
			assert.Equal("GOOGLE_RECAPTCHA", sp.Get("redirectOptions.type").String(), "priority 12 rule has expected redirect type")
		}

		// 	Rule 13
		spRule13 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 13 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range spRule13.Array() {
			assert.False(sp.Get("preview").Bool(), "priority 13 rule Preview is set to False")
			assert.Equal("rate_based_ban", sp.Get("action").String(), "priority 13 rule has expected action")
			assert.Equal("Rate based ban for address from project dropten as soon as they cross rate limit threshold", sp.Get("description").String(), "priority 13 rule has expected description")
			assert.Equal("SRC_IPS_V1", sp.Get("match.versionedExpr").String(), "priority 13 rule has expected redirect type")

			srcIpRanges := sp.Get("match.config.srcIpRanges").Array()
			assert.Equal(2, len(srcIpRanges), "priority 13 rule found only 2 IP address")
			assert.Equal(srcIpRanges[0].String(), "45.116.227.70", "priority 13 rule found first valid cidr range")
			assert.Equal(srcIpRanges[1].String(), "190.217.68.213", "priority 13 rule found second valid cidr range")
			assert.Equal("120", sp.Get("rateLimitOptions.banDurationSec").String(), "priority 13 rule has Rate limit ban duration")
			assert.Equal("allow", sp.Get("rateLimitOptions.conformAction").String(), "priority 13 rule has Rate limit confirm action")
			assert.Equal("ALL", sp.Get("rateLimitOptions.enforceOnKey").String(), "priority 13 rule has Rate limit Enforce on key")
			assert.Equal("deny(502)", sp.Get("rateLimitOptions.exceedAction").String(), "priority 13 rule has Rate limit exceed action")
			assert.Equal("10", sp.Get("rateLimitOptions.rateLimitThreshold.count").String(), "priority 13 rule has Rate limit threshold count")
			assert.Equal("60", sp.Get("rateLimitOptions.rateLimitThreshold.intervalSec").String(), "priority 13 rule has Rate limit threshold interval")
		}

		// 	Rule 14
		spRule14 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 14 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range spRule14.Array() {
			assert.False(sp.Get("preview").Bool(), "priority 14 rule Preview is set to False")
			assert.Equal("rate_based_ban", sp.Get("action").String(), "priority 14 rule has expected action")
			assert.Equal("Rate based ban for address from project dropthirty only if they cross banned threshold", sp.Get("description").String(), "priority 14 rule has expected description")
			assert.Equal("SRC_IPS_V1", sp.Get("match.versionedExpr").String(), "priority 14 rule has expected redirect type")

			srcIpRanges := sp.Get("match.config.srcIpRanges").Array()
			assert.Equal(2, len(srcIpRanges), "priority 14 rule found only 2 IP address")
			assert.Equal(srcIpRanges[0].String(), "45.116.227.70", "priority 14 rule found first valid cidr range")
			assert.Equal(srcIpRanges[1].String(), "190.217.68.213", "priority 14 rule found second valid cidr range")
			assert.Equal("300", sp.Get("rateLimitOptions.banDurationSec").String(), "priority 14 rule has Rate limit ban duration")
			assert.Equal("1000", sp.Get("rateLimitOptions.banThreshold.count").String(), "priority 14 rule has Rate limit threshold count")
			assert.Equal("300", sp.Get("rateLimitOptions.banThreshold.intervalSec").String(), "priority 14 rule has Rate limit threshold interval")
			assert.Equal("allow", sp.Get("rateLimitOptions.conformAction").String(), "priority 14 rule has Rate limit confirm action")
			assert.Equal("ALL", sp.Get("rateLimitOptions.enforceOnKey").String(), "priority 14 rule has Rate limit Enforce on key")
			assert.Equal("deny(502)", sp.Get("rateLimitOptions.exceedAction").String(), "priority 14 rule has Rate limit exceed action")
			assert.Equal("10", sp.Get("rateLimitOptions.rateLimitThreshold.count").String(), "priority 14 rule has Rate limit threshold count")
			assert.Equal("60", sp.Get("rateLimitOptions.rateLimitThreshold.intervalSec").String(), "priority 14 rule has Rate limit threshold interval")
		}

		// 	Rule 15
		spRule15 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 15 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range spRule15.Array() {
			assert.False(sp.Get("preview").Bool(), "priority 15 rule Preview is set to False")
			assert.Equal("throttle", sp.Get("action").String(), "priority 15 rule has expected action")
			assert.Equal("Throttle IP addresses from project droptwenty", sp.Get("description").String(), "priority 15 rule has expected description")
			assert.Equal("SRC_IPS_V1", sp.Get("match.versionedExpr").String(), "priority 15 rule has expected redirect type")

			srcIpRanges := sp.Get("match.config.srcIpRanges").Array()
			assert.Equal(2, len(srcIpRanges), "priority 15 rule found only 2 IP address")
			assert.Equal(srcIpRanges[0].String(), "45.116.227.71", "priority 15 rule found first valid cidr range")
			assert.Equal(srcIpRanges[1].String(), "190.217.68.214", "priority 15 rule found second valid cidr range")
			assert.Equal("allow", sp.Get("rateLimitOptions.conformAction").String(), "priority 15 rule has Rate limit confirm action")
			assert.Equal("", sp.Get("rateLimitOptions.enforceOnKey").String(), "priority 15 rule has Rate limit Enforce on key")
			assert.Equal("deny(502)", sp.Get("rateLimitOptions.exceedAction").String(), "priority 15 rule has Rate limit exceed action")
			assert.Equal("10", sp.Get("rateLimitOptions.rateLimitThreshold.count").String(), "priority 15 rule has Rate limit threshold count")
			assert.Equal("60", sp.Get("rateLimitOptions.rateLimitThreshold.intervalSec").String(), "priority 15 rule has Rate limit threshold interval")
		}

		// 	Rule 21
		spRule21 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 21 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range spRule21.Array() {
			assert.False(sp.Get("preview").Bool(), "priority 21 rule Preview is set to False")
			assert.Equal("allow", sp.Get("action").String(), "priority 21 rule has expected action")
			assert.Equal("Allow specific Regions", sp.Get("description").String(), "priority 21 rule has expected description")
			assert.Equal("'[US,AU,BE]'.contains(origin.region_code)\n", sp.Get("match.expr.expression").String(), "priority 21 rule has expected expression")
		}

		// 	Rule 22
		spRule22 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 22 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range spRule22.Array() {
			assert.False(sp.Get("preview").Bool(), "priority 22 rule Preview is set to False")
			assert.Equal("deny(502)", sp.Get("action").String(), "priority 22 rule has expected action")
			assert.Equal("Deny Specific IP address", sp.Get("description").String(), "priority 22 rule has expected description")
			assert.Equal("inIpRange(origin.ip, '47.185.201.155/32')\n", sp.Get("match.expr.expression").String(), "priority 22 rule has expected expression")
		}

		// 	Rule 23
		spRule23 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 23 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range spRule23.Array() {
			assert.False(sp.Get("preview").Bool(), "priority 23 rule Preview is set to False")
			assert.Equal("throttle", sp.Get("action").String(), "priority 23 rule has expected action")
			assert.Equal("Throttle specific IP address in US Region", sp.Get("description").String(), "priority 23 rule has expected description")
			assert.Equal("origin.region_code == \"US\" && inIpRange(origin.ip, '47.185.201.159/32')\n", sp.Get("match.expr.expression").String(), "priority 23 rule has expected expression")
			assert.Equal("allow", sp.Get("rateLimitOptions.conformAction").String(), "priority 23 rule has Rate limit confirm action")
			assert.Equal("", sp.Get("rateLimitOptions.enforceOnKey").String(), "priority 23 rule has Rate limit Enforce on key")
			assert.Equal("deny(502)", sp.Get("rateLimitOptions.exceedAction").String(), "priority 23 rule has Rate limit exceed action")
			assert.Equal("10", sp.Get("rateLimitOptions.rateLimitThreshold.count").String(), "priority 23 rule has Rate limit threshold count")
			assert.Equal("60", sp.Get("rateLimitOptions.rateLimitThreshold.intervalSec").String(), "priority 23 rule has Rate limit threshold interval")
		}

		// 	Rule 24
		spRule24 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 24 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range spRule24.Array() {
			assert.False(sp.Get("preview").Bool(), "priority 24 rule Preview is set to False")
			assert.Equal("rate_based_ban", sp.Get("action").String(), "priority 24 rule has expected action")
			assert.Empty(sp.Get("description").String(), "priority 24 rule has expected description")
			assert.Equal("inIpRange(origin.ip, '47.185.201.160/32')\n", sp.Get("match.expr.expression").String(), "priority 24 rule has expected expression")
			assert.Equal("120", sp.Get("rateLimitOptions.banDurationSec").String(), "priority 24 rule has Rate limit ban duration")
			assert.Equal("10000", sp.Get("rateLimitOptions.banThreshold.count").String(), "priority 24 rule has Rate limit threshold count")
			assert.Equal("600", sp.Get("rateLimitOptions.banThreshold.intervalSec").String(), "priority 24 rule has Rate limit threshold interval")
			assert.Equal("allow", sp.Get("rateLimitOptions.conformAction").String(), "priority 24 rule has Rate limit confirm action")
			assert.Equal("ALL", sp.Get("rateLimitOptions.enforceOnKey").String(), "priority 24 rule has Rate limit Enforce on key")
			assert.Equal("deny(502)", sp.Get("rateLimitOptions.exceedAction").String(), "priority 24 rule has Rate limit exceed action")
			assert.Equal("10", sp.Get("rateLimitOptions.rateLimitThreshold.count").String(), "priority 24 rule has Rate limit threshold count")
			assert.Equal("60", sp.Get("rateLimitOptions.rateLimitThreshold.intervalSec").String(), "priority 24 rule has Rate limit threshold interval")
		}

		// 	Rule 100
		spRule100 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 100 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range spRule100.Array() {
			assert.True(sp.Get("preview").Bool(), "priority 100 rule Preview is set to True")
			assert.Equal("deny(502)", sp.Get("action").String(), "priority 100 rule has expected action")
			assert.Equal("test Sensitivity level policies", sp.Get("description").String(), "priority 100 rule has expected description")
			assert.Equal("evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 4, 'opt_out_rule_ids': ['owasp-crs-v030301-id942350-sqli', 'owasp-crs-v030301-id942360-sqli']})\n", sp.Get("match.expr.expression").String(), "priority 100 rule has expected expression")
		}
	})
	casp.Test()
}

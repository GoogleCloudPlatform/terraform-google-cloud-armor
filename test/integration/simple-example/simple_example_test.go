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

package simple_example

import (
	"fmt"
	"testing"

	"github.com/GoogleCloudPlatform/cloud-foundation-toolkit/infra/blueprint-test/pkg/gcloud"
	"github.com/GoogleCloudPlatform/cloud-foundation-toolkit/infra/blueprint-test/pkg/tft"
	"github.com/stretchr/testify/assert"
)

func TestSimpleExample(t *testing.T) {
	casp := tft.NewTFBlueprintTest(t)

	casp.DefineVerify(func(assert *assert.Assertions) {
		casp.DefaultVerify(assert)

		projectId := casp.GetStringOutput("project_id")
		policyName := casp.GetStringOutput("policy_name")

		sp_name := gcloud.Run(t, fmt.Sprintf("compute security-policies describe %s --project %s", policyName, projectId))
		for _, sp := range sp_name.Array() {
			assert.Equal(policyName, sp.Get("name").String(), "has expected name")
			assert.Equal("STANDARD", sp.Get("advancedOptionsConfig.jsonParsing").String(), "has value STANDARD")
			assert.Equal("VERBOSE", sp.Get("advancedOptionsConfig.logLevel").String(), "has value VERBOSE")
			assert.Equal("STANDARD", sp.Get("adaptiveProtectionConfig.layer7DdosDefenseConfig.ruleVisibility").String(), "has value STANDARD")
			assert.True(sp.Get("adaptiveProtectionConfig.layer7DdosDefenseConfig.enable").Bool(), "layer7DdosDefenseConfig.enable set to True")
		}

		// 	Rule 1
		sp_rule1 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 1 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range sp_rule1.Array() {
			assert.Equal("deny(502)", sp.Get("action").String(), "priority 1 rule has expected action")
			assert.Equal("evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 4})", sp.Get("match.expr.expression").String(), "priority 1 rule has expected rule expression")
			assert.Empty(sp.Get("description").String(), "priority 2 rule has expected description")
			assert.False(sp.Get("preview").Bool(), "priority 1 rule Preview is set to False")
		}

		// 	Rule 2
		sp_rule2 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 2 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range sp_rule2.Array() {
			assert.Equal("deny(502)", sp.Get("action").String(), "priority 2 rule has expected action")
			assert.Equal("evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 2, 'opt_out_rule_ids': ['owasp-crs-v030301-id941380-xss','owasp-crs-v030301-id941280-xss']})", sp.Get("match.expr.expression").String(), "priority 2 rule has expected rule expression")
			assert.Equal("XSS Sensitivity Level 2 with excluded rules", sp.Get("description").String(), "priority 2 rule has expected description")
			assert.True(sp.Get("preview").Bool(), "priority 2 rule Preview is set to True")
		}
		sp_rule3 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 3 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range sp_rule3.Array() {
			assert.Equal("deny(502)", sp.Get("action").String(), "priority 3 rule has expected action")
			assert.Equal("evaluatePreconfiguredWaf('php-v33-stable', {'sensitivity': 0, 'opt_in_rule_ids': ['owasp-crs-v030301-id933190-php','owasp-crs-v030301-id933111-php']})", sp.Get("match.expr.expression").String(), "priority 3 rule has expected rule expression")
			assert.Equal("PHP Sensitivity Level 0 with included rules", sp.Get("description").String(), "priority 3 rule has expected description")
			assert.False(sp.Get("preview").Bool(), "priority 3 rule Preview is set to False")
		}

		// 	Rule 11
		sp_rule11 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 11 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range sp_rule11.Array() {
			assert.True(sp.Get("preview").Bool(), "priority 11 rule Preview is set to True")
			assert.Equal("deny(502)", sp.Get("action").String(), "priority 11 rule has expected action")
			assert.Equal("Deny Malicious IP address from project honeypot", sp.Get("description").String(), "priority 11 rule has expected description")
			assert.Equal("SRC_IPS_V1", sp.Get("match.versionedExpr").String(), "priority 11 rule has expected redirect type")
			srcIpRanges := sp.Get("match.config.srcIpRanges").Array()
			assert.Equal(5, len(srcIpRanges), "found only 5 IP address")
		}

		// 	Rule 12
		sp_rule12 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 12 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range sp_rule12.Array() {
			assert.False(sp.Get("preview").Bool(), "priority 12 rule Preview is set to False")
			assert.Equal("redirect", sp.Get("action").String(), "priority 12 rule has expected action")
			assert.Equal("Redirect IP address from project RD", sp.Get("description").String(), "priority 12 rule has expected description")
			assert.Equal("SRC_IPS_V1", sp.Get("match.versionedExpr").String(), "priority 12 rule has expected redirect type")

			srcIpRanges := sp.Get("match.config.srcIpRanges").Array()
			assert.Equal(2, len(srcIpRanges), "priority 12 rule found only 2 IP address")
			assert.Equal(srcIpRanges[0].String(), "45.116.227.99", "priority 12 rule found first valid cidr range")
			assert.Equal(srcIpRanges[1].String(), "190.217.68.215", "priority 12 rule found second valid cidr range")
			assert.Equal("https://www.example.com", sp.Get("redirectOptions.target").String(), "priority 12 rule has expected redirect target")
			assert.Equal("EXTERNAL_302", sp.Get("redirectOptions.type").String(), "priority 12 rule has expected redirect type")
		}

		// 	Rule 13
		sp_rule13 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 13 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range sp_rule13.Array() {
			assert.False(sp.Get("preview").Bool(), "priority 13 rule Preview is set to False")
			assert.Equal("rate_based_ban", sp.Get("action").String(), "priority 13 rule has expected action")
			assert.Equal("Rate based ban for address from project dropten as soon as they cross rate limit threshold", sp.Get("description").String(), "priority 13 rule has expected description")
			assert.Equal("SRC_IPS_V1", sp.Get("match.versionedExpr").String(), "priority 13 rule has expected redirect type")

			srcIpRanges := sp.Get("match.config.srcIpRanges").Array()
			assert.Equal(2, len(srcIpRanges), "priority 13 rule found only 2 IP address")
			assert.Equal(srcIpRanges[0].String(), "45.116.227.70", "priority 13 rule found first valid cidr range")
			assert.Equal(srcIpRanges[1].String(), "190.217.68.213/32", "priority 13 rule found second valid cidr range")
			assert.Equal("120", sp.Get("rateLimitOptions.banDurationSec").String(), "priority 13 rule has Rate limit ban duration")
			assert.Equal("allow", sp.Get("rateLimitOptions.conformAction").String(), "priority 13 rule has Rate limit confirm action")
			assert.Equal("ALL", sp.Get("rateLimitOptions.enforceOnKey").String(), "priority 13 rule has Rate limit Enforce on key")
			assert.Equal("deny(502)", sp.Get("rateLimitOptions.exceedAction").String(), "priority 13 rule has Rate limit exceed action")
			assert.Equal("10", sp.Get("rateLimitOptions.rateLimitThreshold.count").String(), "priority 13 rule has Rate limit threshold count")
			assert.Equal("60", sp.Get("rateLimitOptions.rateLimitThreshold.intervalSec").String(), "priority 13 rule has Rate limit threshold interval")
		}

		// 	Rule 14
		sp_rule14 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 14 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range sp_rule14.Array() {
			assert.False(sp.Get("preview").Bool(), "priority 14 rule Preview is set to False")
			assert.Equal("rate_based_ban", sp.Get("action").String(), "priority 14 rule has expected action")
			assert.Equal("Rate based ban for address from project dropthirty only if they cross banned threshold", sp.Get("description").String(), "priority 14 rule has expected description")
			assert.Equal("SRC_IPS_V1", sp.Get("match.versionedExpr").String(), "priority 14 rule has expected redirect type")

			srcIpRanges := sp.Get("match.config.srcIpRanges").Array()
			assert.Equal(2, len(srcIpRanges), "priority 14 rule found only 2 IP address")
			assert.Equal(srcIpRanges[0].String(), "45.116.227.70", "priority 14 rule found first valid cidr range")
			assert.Equal(srcIpRanges[1].String(), "190.217.68.213", "priority 14 rule found second valid cidr range")
			assert.Equal("600", sp.Get("rateLimitOptions.banDurationSec").String(), "priority 14 rule has Rate limit ban duration")
			assert.Equal("1000", sp.Get("rateLimitOptions.banThreshold.count").String(), "priority 14 rule has Rate limit threshold count")
			assert.Equal("300", sp.Get("rateLimitOptions.banThreshold.intervalSec").String(), "priority 14 rule has Rate limit threshold interval")
			assert.Equal("allow", sp.Get("rateLimitOptions.conformAction").String(), "priority 14 rule has Rate limit confirm action")
			assert.Equal("ALL", sp.Get("rateLimitOptions.enforceOnKey").String(), "priority 14 rule has Rate limit Enforce on key")
			assert.Equal("deny(502)", sp.Get("rateLimitOptions.exceedAction").String(), "priority 14 rule has Rate limit exceed action")
			assert.Equal("10", sp.Get("rateLimitOptions.rateLimitThreshold.count").String(), "priority 14 rule has Rate limit threshold count")
			assert.Equal("60", sp.Get("rateLimitOptions.rateLimitThreshold.intervalSec").String(), "priority 14 rule has Rate limit threshold interval")
		}

		// 	Rule 15
		sp_rule15 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 15 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range sp_rule15.Array() {
			assert.False(sp.Get("preview").Bool(), "priority 15 rule Preview is set to False")
			assert.Equal("throttle", sp.Get("action").String(), "priority 15 rule has expected action")
			assert.Equal("Throttle IP addresses from project droptwenty", sp.Get("description").String(), "priority 15 rule has expected description")
			assert.Equal("SRC_IPS_V1", sp.Get("match.versionedExpr").String(), "priority 15 rule has expected redirect type")

			srcIpRanges := sp.Get("match.config.srcIpRanges").Array()
			assert.Equal(2, len(srcIpRanges), "priority 15 rule found only 2 IP address")
			assert.Equal(srcIpRanges[0].String(), "45.116.227.71", "priority 15 rule found first valid cidr range")
			assert.Equal(srcIpRanges[1].String(), "190.217.68.214", "priority 15 rule found second valid cidr range")
			assert.Equal("allow", sp.Get("rateLimitOptions.conformAction").String(), "priority 15 rule has Rate limit confirm action")
			assert.Equal("ALL", sp.Get("rateLimitOptions.enforceOnKey").String(), "priority 15 rule has Rate limit Enforce on key")
			assert.Equal("deny(502)", sp.Get("rateLimitOptions.exceedAction").String(), "priority 15 rule has Rate limit exceed action")
			assert.Equal("10", sp.Get("rateLimitOptions.rateLimitThreshold.count").String(), "priority 15 rule has Rate limit threshold count")
			assert.Equal("60", sp.Get("rateLimitOptions.rateLimitThreshold.intervalSec").String(), "priority 15 rule has Rate limit threshold interval")
		}

		// 	Rule 21
		sp_rule21 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 21 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range sp_rule21.Array() {
			assert.False(sp.Get("preview").Bool(), "priority 21 rule Preview is set to False")
			assert.Equal("deny(502)", sp.Get("action").String(), "priority 21 rule has expected action")
			assert.Equal("Deny specific Regions", sp.Get("description").String(), "priority 21 rule has expected description")
			assert.Equal("'[AU,BE]'.contains(origin.region_code)\n", sp.Get("match.expr.expression").String(), "priority 21 rule has expected expression")
		}

		// 	Rule 22
		sp_rule22 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 22 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range sp_rule22.Array() {
			assert.False(sp.Get("preview").Bool(), "priority 22 rule Preview is set to False")
			assert.Equal("deny(502)", sp.Get("action").String(), "priority 22 rule has expected action")
			assert.Equal("Deny Specific IP address", sp.Get("description").String(), "priority 22 rule has expected description")
			assert.Equal("inIpRange(origin.ip, '47.185.201.155/32')\n", sp.Get("match.expr.expression").String(), "priority 22 rule has expected expression")
		}

		// 	Rule 23
		sp_rule23 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 23 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range sp_rule23.Array() {
			assert.False(sp.Get("preview").Bool(), "priority 23 rule Preview is set to False")
			assert.Equal("throttle", sp.Get("action").String(), "priority 23 rule has expected action")
			assert.Equal("Throttle specific IP address in US Region", sp.Get("description").String(), "priority 23 rule has expected description")
			assert.Equal("origin.region_code == \"US\" && inIpRange(origin.ip, '47.185.201.159/32')\n", sp.Get("match.expr.expression").String(), "priority 23 rule has expected expression")
			assert.Equal("allow", sp.Get("rateLimitOptions.conformAction").String(), "priority 23 rule has Rate limit confirm action")
			assert.Equal("ALL", sp.Get("rateLimitOptions.enforceOnKey").String(), "priority 23 rule has Rate limit Enforce on key")
			assert.Equal("deny(502)", sp.Get("rateLimitOptions.exceedAction").String(), "priority 23 rule has Rate limit exceed action")
			assert.Equal("10", sp.Get("rateLimitOptions.rateLimitThreshold.count").String(), "priority 23 rule has Rate limit threshold count")
			assert.Equal("60", sp.Get("rateLimitOptions.rateLimitThreshold.intervalSec").String(), "priority 23 rule has Rate limit threshold interval")
		}

		// 	Rule 24
		sp_rule24 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 24 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range sp_rule24.Array() {
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
		sp_rule100 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 100 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range sp_rule100.Array() {
			assert.True(sp.Get("preview").Bool(), "priority 100 rule Preview is set to True")
			assert.Equal("deny(502)", sp.Get("action").String(), "priority 100 rule has expected action")
			assert.Equal("Deny pre-configured rule java-v33-stable at sensitivity level 3", sp.Get("description").String(), "priority 100 rule has expected description")
			assert.Equal("evaluatePreconfiguredWaf('java-v33-stable', {'sensitivity': 3, 'opt_out_rule_ids': ['owasp-crs-v030301-id944240-java', 'owasp-crs-v030301-id944120-java']})\n", sp.Get("match.expr.expression").String(), "priority 100 rule has expected expression")
		}

	})
	casp.Test()
}

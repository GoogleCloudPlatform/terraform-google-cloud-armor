// Copyright 2024 Google LLC
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

package security_policy_enterprise

import (
	"fmt"
	"testing"

	"github.com/GoogleCloudPlatform/cloud-foundation-toolkit/infra/blueprint-test/pkg/gcloud"
	"github.com/GoogleCloudPlatform/cloud-foundation-toolkit/infra/blueprint-test/pkg/tft"
	"github.com/stretchr/testify/assert"
)

func TestGlobalSecurityPolicyEnterprise(t *testing.T) {
	casp := tft.NewTFBlueprintTest(t)

	casp.DefineVerify(func(assert *assert.Assertions) {
		casp.DefaultVerify(assert)

		projectId := casp.GetStringOutput("project_id")
		policyName := casp.GetStringOutput("policy_name")

		spName := gcloud.Run(t, fmt.Sprintf("compute security-policies describe %s --project %s", policyName, projectId))
		for _, sp := range spName.Array() {
			pname := sp.Get("name").String()
			assert.Equal(policyName, pname, "has expected name")
			assert.Equal("Test Cloud Armor security policy with with rules supported by Cloud Armor Enterprise (Former Managed Protection Plus - CAMP+)", sp.Get("description").String(), "has expected description")
			assert.Equal("CLOUD_ARMOR", sp.Get("type").String(), "has expected name")
			assert.Equal("STANDARD", sp.Get("adaptiveProtectionConfig.layer7DdosDefenseConfig.ruleVisibility").String(), "Mismatched adaptiveProtectionConfig.layer7DdosDefenseConfig.ruleVisibility")
			assert.True(sp.Get("adaptiveProtectionConfig.layer7DdosDefenseConfig.enable").Bool(), "adaptiveProtectionConfig.layer7DdosDefenseConfig.enable is not true")
		}
		// 	Rule 300
		spRule300 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 300 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range spRule300.Array() {
			assert.Equal("deny(502)", sp.Get("action").String(), "priority 300 rule has mismatched action")
			assert.Equal("Deny IP addresses known to attack web applications", sp.Get("description").String(), "rule 400 has mismatched description")
			assert.Equal("evaluateThreatIntelligence('iplist-known-malicious-ips', ['47.100.100.100', '47.189.12.139'])", sp.Get("match.expr.expression").String(), "priority 300 rule has mismatched rule expression")
			assert.False(sp.Get("preview").Bool(), "priority 300 rule Preview is set to True")
		}
		// 	Rule 400
		spRule400 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 400 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range spRule400.Array() {
			assert.Equal("deny(502)", sp.Get("action").String(), "priority 400 rule has mismatched action")
			assert.Equal("Deny Tor exit nodes IP addresses", sp.Get("description").String(), "rule 400 has mismatched description")
			assert.Equal("evaluateThreatIntelligence('iplist-tor-exit-nodes')", sp.Get("match.expr.expression").String(), "priority 400 rule has mismatched rule expression")
			assert.False(sp.Get("preview").Bool(), "priority 400 rule Preview is set to True")
		}

	})
	casp.Test()
}

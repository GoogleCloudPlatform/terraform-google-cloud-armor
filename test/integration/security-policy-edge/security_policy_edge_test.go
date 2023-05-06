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

func TestSecurityPolicyEdge(t *testing.T) {
	casp := tft.NewTFBlueprintTest(t)

	casp.DefineVerify(func(assert *assert.Assertions) {
		casp.DefaultVerify(assert)

		projectId := casp.GetStringOutput("project_id")
		policyName := casp.GetStringOutput("policy_name")

		sp_name := gcloud.Run(t, fmt.Sprintf("compute security-policies describe %s --project %s", policyName, projectId))
		for _, sp := range sp_name.Array() {
			pname := sp.Get("name").String()
			assert.Equal(policyName, pname, "has expected name")
			assert.Equal("Test Cloud Armor Edge security policy", sp.Get("description").String(), "has expected description")
			assert.Equal("CLOUD_ARMOR_EDGE", sp.Get("type").String(), "has expected name")
		}

		// 	Rule 1
		sp_rule1 := gcloud.Run(t, fmt.Sprintf("compute security-policies rules describe 1 --security-policy=%s --project %s", policyName, projectId))
		for _, sp := range sp_rule1.Array() {
			assert.Equal("allow", sp.Get("action").String(), "priority 1 rule has expected action")
			assert.Equal("origin.region_code == \"US\"\n", sp.Get("match.expr.expression").String(), "priority 1 rule has expected expression")
			assert.Equal("Allow specific Regions", sp.Get("description").String(), "priority 1 rule has expected description")
			assert.False(sp.Get("preview").Bool(), "priority 1 rule Preview is set to False")
		}
	})
	casp.Test()
}

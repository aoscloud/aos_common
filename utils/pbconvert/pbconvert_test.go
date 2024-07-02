// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2022 Renesas Electronics Corporation.
// Copyright (C) 2022 EPAM Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pbconvert_test

import (
	"os"
	"reflect"
	"testing"

	"github.com/aosedge/aos_common/aostypes"
	"github.com/aosedge/aos_common/api/cloudprotocol"
	pbcommon "github.com/aosedge/aos_common/api/common"
	pbsm "github.com/aosedge/aos_common/api/servicemanager"
	"github.com/aosedge/aos_common/utils/pbconvert"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

/***********************************************************************************************************************
 * Init
 **********************************************************************************************************************/

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
		TimestampFormat:  "2006-01-02 15:04:05.000",
		FullTimestamp:    true,
	})
	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)
}

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

func TestInstanceFilterToPB(t *testing.T) {
	type testFilter struct {
		expectedFilter *pbsm.InstanceFilter
		aosFilter      cloudprotocol.InstanceFilter
	}

	testData := []testFilter{
		{
			expectedFilter: &pbsm.InstanceFilter{ServiceId: "s1", SubjectId: "subj1", Instance: 1},
			aosFilter:      cloudprotocol.NewInstanceFilter("s1", "subj1", 1),
		},
		{
			expectedFilter: &pbsm.InstanceFilter{ServiceId: "s1", SubjectId: "", Instance: 1},
			aosFilter:      cloudprotocol.NewInstanceFilter("s1", "", 1),
		},
		{
			expectedFilter: &pbsm.InstanceFilter{ServiceId: "s1", SubjectId: "subj1", Instance: -1},
			aosFilter:      cloudprotocol.NewInstanceFilter("s1", "subj1", -1),
		},
		{
			expectedFilter: &pbsm.InstanceFilter{ServiceId: "s1", SubjectId: "", Instance: -1},
			aosFilter:      cloudprotocol.NewInstanceFilter("s1", "", -1),
		},
		{
			expectedFilter: &pbsm.InstanceFilter{ServiceId: "", SubjectId: "", Instance: -1},
			aosFilter:      cloudprotocol.NewInstanceFilter("", "", -1),
		},
	}

	for _, testItem := range testData {
		instance := pbconvert.InstanceFilterToPB(testItem.aosFilter)

		if !proto.Equal(instance, testItem.expectedFilter) {
			t.Error("Incorrect instance")
		}
	}
}

func TestInstanceIdentToPB(t *testing.T) {
	expectedInstance := &pbcommon.InstanceIdent{ServiceId: "s1", SubjectId: "subj1", Instance: 2}

	pbInstance := pbconvert.InstanceIdentToPB(
		aostypes.InstanceIdent{ServiceID: "s1", SubjectID: "subj1", Instance: 2})

	if !proto.Equal(pbInstance, expectedInstance) {
		t.Error("Incorrect instance")
	}
}

func TestInstanceIdentFromPB(t *testing.T) {
	expectedInstance := aostypes.InstanceIdent{ServiceID: "s1", SubjectID: "subj1", Instance: 2}

	receivedInstance := pbconvert.NewInstanceIdentFromPB(
		&pbcommon.InstanceIdent{ServiceId: "s1", SubjectId: "subj1", Instance: 2})

	if expectedInstance != receivedInstance {
		t.Error("Incorrect instance")
	}
}

func TestNetworkParametersToPB(t *testing.T) {
	expectedNetwork := &pbsm.NetworkParameters{
		Ip:         "172.18.0.1",
		Subnet:     "172.18.0.0/16",
		DnsServers: []string{"10.10.0.1"},
		Rules: []*pbsm.FirewallRule{
			{
				Proto:   "tcp",
				DstIp:   "172.19.0.1",
				SrcIp:   "172.18.0.1",
				DstPort: "8080",
			},
		},
	}

	pbNetwork := pbconvert.NetworkParametersToPB(
		aostypes.NetworkParameters{
			IP:         "172.18.0.1",
			Subnet:     "172.18.0.0/16",
			DNSServers: []string{"10.10.0.1"},
			FirewallRules: []aostypes.FirewallRule{
				{
					Proto:   "tcp",
					DstIP:   "172.19.0.1",
					SrcIP:   "172.18.0.1",
					DstPort: "8080",
				},
			},
		})

	if !proto.Equal(pbNetwork, expectedNetwork) {
		t.Error("Incorrect network parameters")
	}
}

func TestNetworkParametersFromPB(t *testing.T) {
	expectedNetwork := aostypes.NetworkParameters{
		IP:         "172.18.0.1",
		Subnet:     "172.18.0.0/16",
		DNSServers: []string{"10.10.0.1"},
		FirewallRules: []aostypes.FirewallRule{
			{
				Proto:   "tcp",
				DstIP:   "172.19.0.1",
				SrcIP:   "172.18.0.1",
				DstPort: "8080",
			},
		},
	}

	receivedNetwork := pbconvert.NewNetworkParametersFromPB(
		&pbsm.NetworkParameters{
			Ip:         "172.18.0.1",
			Subnet:     "172.18.0.0/16",
			DnsServers: []string{"10.10.0.1"},
			Rules: []*pbsm.FirewallRule{
				{
					Proto:   "tcp",
					DstIp:   "172.19.0.1",
					SrcIp:   "172.18.0.1",
					DstPort: "8080",
				},
			},
		})

	if !reflect.DeepEqual(expectedNetwork, receivedNetwork) {
		t.Error("Incorrect network parameters")
	}
}

func TestErrorInfoToPB(t *testing.T) {
	expectedErrorInfo := &pbcommon.ErrorInfo{AosCode: 42, ExitCode: 5, Message: "error"}

	pbErrorInfo := pbconvert.ErrorInfoToPB(
		&cloudprotocol.ErrorInfo{AosCode: 42, ExitCode: 5, Message: "error"})

	if !proto.Equal(pbErrorInfo, expectedErrorInfo) {
		t.Error("Incorrect instance")
	}
}

func TestErrorInfoFromPB(t *testing.T) {
	expectedErrorInfo := &cloudprotocol.ErrorInfo{AosCode: 42, ExitCode: 5, Message: "error"}

	receivedErrorInfo := pbconvert.NewErrorInfoFromPB(
		&pbcommon.ErrorInfo{AosCode: 42, ExitCode: 5, Message: "error"})

	if *expectedErrorInfo != *receivedErrorInfo {
		t.Error("Incorrect instance")
	}
}

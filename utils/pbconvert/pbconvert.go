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

package pbconvert

import (
	"github.com/aosedge/aos_common/aostypes"
	"github.com/aosedge/aos_common/api/cloudprotocol"
	pbcommon "github.com/aosedge/aos_common/api/common"
	pbsm "github.com/aosedge/aos_common/api/servicemanager"
)

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

func InstanceFilterToPB(filter cloudprotocol.InstanceFilter) *pbsm.InstanceFilter {
	ident := &pbsm.InstanceFilter{ServiceId: "", SubjectId: "", Instance: -1}

	if filter.ServiceID != nil {
		ident.ServiceId = *filter.ServiceID
	}

	if filter.SubjectID != nil {
		ident.SubjectId = *filter.SubjectID
	}

	if filter.Instance != nil {
		ident.Instance = (int64)(*filter.Instance)
	}

	return ident
}

func InstanceIdentToPB(ident aostypes.InstanceIdent) *pbcommon.InstanceIdent {
	return &pbcommon.InstanceIdent{ServiceId: ident.ServiceID, SubjectId: ident.SubjectID, Instance: ident.Instance}
}

func ErrorInfoToPB(errorInfo *cloudprotocol.ErrorInfo) *pbcommon.ErrorInfo {
	if errorInfo == nil {
		return nil
	}

	return &pbcommon.ErrorInfo{
		AosCode:  int32(errorInfo.AosCode),
		ExitCode: int32(errorInfo.ExitCode),
		Message:  errorInfo.Message,
	}
}

func NetworkParametersToPB(params aostypes.NetworkParameters) *pbsm.NetworkParameters {
	networkParams := &pbsm.NetworkParameters{
		Ip:         params.IP,
		Subnet:     params.Subnet,
		VlanId:     params.VlanID,
		DnsServers: make([]string, len(params.DNSServers)),
		Rules:      make([]*pbsm.FirewallRule, len(params.FirewallRules)),
	}

	copy(networkParams.GetDnsServers(), params.DNSServers)

	for i, rule := range params.FirewallRules {
		networkParams.Rules[i] = &pbsm.FirewallRule{
			DstIp:   rule.DstIP,
			SrcIp:   rule.SrcIP,
			DstPort: rule.DstPort,
			Proto:   rule.Proto,
		}
	}

	return networkParams
}

func NewInstanceIdentFromPB(ident *pbcommon.InstanceIdent) aostypes.InstanceIdent {
	return aostypes.InstanceIdent{
		ServiceID: ident.GetServiceId(),
		SubjectID: ident.GetSubjectId(),
		Instance:  ident.GetInstance(),
	}
}

func NewNetworkParametersFromPB(params *pbsm.NetworkParameters) aostypes.NetworkParameters {
	networkParams := aostypes.NetworkParameters{
		IP:            params.GetIp(),
		Subnet:        params.GetSubnet(),
		VlanID:        params.GetVlanId(),
		DNSServers:    make([]string, len(params.GetDnsServers())),
		FirewallRules: make([]aostypes.FirewallRule, len(params.GetRules())),
	}

	copy(networkParams.DNSServers, params.GetDnsServers())

	for i, rule := range params.GetRules() {
		networkParams.FirewallRules[i] = aostypes.FirewallRule{
			DstIP:   rule.GetDstIp(),
			SrcIP:   rule.GetSrcIp(),
			DstPort: rule.GetDstPort(),
			Proto:   rule.GetProto(),
		}
	}

	return networkParams
}

func NewErrorInfoFromPB(errorInfo *pbcommon.ErrorInfo) *cloudprotocol.ErrorInfo {
	if errorInfo == nil {
		return nil
	}

	return &cloudprotocol.ErrorInfo{
		AosCode:  int(errorInfo.GetAosCode()),
		ExitCode: int(errorInfo.GetExitCode()),
		Message:  errorInfo.GetMessage(),
	}
}

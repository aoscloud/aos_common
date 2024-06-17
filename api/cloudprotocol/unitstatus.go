// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2021 Renesas Electronics Corporation.
// Copyright (C) 2021 EPAM Systems, Inc.
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

package cloudprotocol

import "github.com/aoscloud/aos_common/aostypes"

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

// UnitStatusMessageType unit status message type.
const UnitStatusMessageType = "unitStatus"

// Instance statuses.
const (
	InstanceStateActivating = "activating"
	InstanceStateActive     = "active"
	InstanceStateInactive   = "inactive"
	InstanceStateFailed     = "failed"
)

// Service/layers/components statuses.
const (
	UnknownStatus     = "unknown"
	PendingStatus     = "pending"
	DownloadingStatus = "downloading"
	DownloadedStatus  = "downloaded"
	InstallingStatus  = "installing"
	InstalledStatus   = "installed"
	RemovingStatus    = "removing"
	RemovedStatus     = "removed"
	ErrorStatus       = "error"
)

// Partition types.
const (
	GenericPartition  = "generic"
	StoragesPartition = "storages"
	StatesPartition   = "states"
	ServicesPartition = "services"
	LayersPartition   = "layers"
)

// Node statuses.
const (
	NodeStatusUnprovisioned = "unprovisioned"
	NodeStatusProvisioned   = "provisioned"
	NodeStatusPaused        = "paused"
	NodeStatusError         = "error"
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// UnitConfigStatus unit config status.
type UnitConfigStatus struct {
	Version   string     `json:"version"`
	Status    string     `json:"status"`
	ErrorInfo *ErrorInfo `json:"errorInfo,omitempty"`
}

// CPUInfo cpu information.
type CPUInfo struct {
	ModelName  string `json:"modelName"`
	NumCores   uint64 `json:"totalNumCores"`
	NumThreads uint64 `json:"totalNumThreads"`
	Arch       string `json:"arch"`
	ArchFamily string `json:"archFamily"`
	MaxDMIPs   uint64 `json:"maxDmips"`
}

// PartitionInfo partition information.
type PartitionInfo struct {
	Name      string   `json:"name"`
	Types     []string `json:"types"`
	TotalSize uint64   `json:"totalSize"`
	Path      string   `json:"-"`
}

// NodeInfo node information.
type NodeInfo struct {
	NodeID     string          `json:"nodeId"`
	NodeType   string          `json:"nodeType"`
	Name       string          `json:"name"`
	Status     string          `json:"status"`
	CPUs       []CPUInfo       `json:"cpus"`
	OSType     string          `json:"osType"`
	MaxDMIPs   uint64          `json:"maxDmips"`
	TotalRAM   uint64          `json:"totalRam"`
	Attrs      []string        `json:"attrs,omitempty"`
	Partitions []PartitionInfo `json:"partitions,omitempty"`
	ErrorInfo  *ErrorInfo      `json:"errorInfo,omitempty"`
}

// ServiceStatus service status.
type ServiceStatus struct {
	ServiceID string     `json:"serviceId"`
	Version   string     `json:"version"`
	Status    string     `json:"status"`
	ErrorInfo *ErrorInfo `json:"errorInfo,omitempty"`
}

// InstanceStatus service instance runtime status.
type InstanceStatus struct {
	aostypes.InstanceIdent
	Version       string     `json:"version"`
	StateChecksum string     `json:"stateChecksum,omitempty"`
	RunState      string     `json:"runState"`
	NodeID        string     `json:"nodeId"`
	ErrorInfo     *ErrorInfo `json:"errorInfo,omitempty"`
}

// LayerStatus layer status.
type LayerStatus struct {
	LayerID   string     `json:"layerId"`
	Digest    string     `json:"digest"`
	Version   string     `json:"version"`
	Status    string     `json:"status"`
	ErrorInfo *ErrorInfo `json:"errorInfo,omitempty"`
}

// ComponentStatus component status.
type ComponentStatus struct {
	ComponentID   string     `json:"componentId"`
	ComponentType string     `json:"componentType"`
	Version       string     `json:"version"`
	Status        string     `json:"status"`
	ErrorInfo     *ErrorInfo `json:"errorInfo,omitempty"`
}

// UnitStatus unit status structure.
type UnitStatus struct {
	MessageType  string             `json:"messageType"`
	IsDeltaInfo  bool               `json:"isDeltaInfo"`
	UnitConfig   []UnitConfigStatus `json:"unitConfig"`
	Nodes        []NodeInfo         `json:"nodes"`
	Services     []ServiceStatus    `json:"services"`
	Instances    []InstanceStatus   `json:"instances"`
	Layers       []LayerStatus      `json:"layers,omitempty"`
	Components   []ComponentStatus  `json:"components"`
	UnitSubjects []string           `json:"unitSubjects"`
}

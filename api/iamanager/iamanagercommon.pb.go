// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.6.1
// source: iamanagercommon.proto

package iamanager

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Permissions struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Permissions map[string]string `protobuf:"bytes,1,rep,name=permissions,proto3" json:"permissions,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Permissions) Reset() {
	*x = Permissions{}
	if protoimpl.UnsafeEnabled {
		mi := &file_iamanagercommon_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Permissions) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Permissions) ProtoMessage() {}

func (x *Permissions) ProtoReflect() protoreflect.Message {
	mi := &file_iamanagercommon_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Permissions.ProtoReflect.Descriptor instead.
func (*Permissions) Descriptor() ([]byte, []int) {
	return file_iamanagercommon_proto_rawDescGZIP(), []int{0}
}

func (x *Permissions) GetPermissions() map[string]string {
	if x != nil {
		return x.Permissions
	}
	return nil
}

type UsersChangedNtf struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Users []string `protobuf:"bytes,1,rep,name=users,proto3" json:"users,omitempty"`
}

func (x *UsersChangedNtf) Reset() {
	*x = UsersChangedNtf{}
	if protoimpl.UnsafeEnabled {
		mi := &file_iamanagercommon_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UsersChangedNtf) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UsersChangedNtf) ProtoMessage() {}

func (x *UsersChangedNtf) ProtoReflect() protoreflect.Message {
	mi := &file_iamanagercommon_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UsersChangedNtf.ProtoReflect.Descriptor instead.
func (*UsersChangedNtf) Descriptor() ([]byte, []int) {
	return file_iamanagercommon_proto_rawDescGZIP(), []int{1}
}

func (x *UsersChangedNtf) GetUsers() []string {
	if x != nil {
		return x.Users
	}
	return nil
}

var File_iamanagercommon_proto protoreflect.FileDescriptor

var file_iamanagercommon_proto_rawDesc = []byte{
	0x0a, 0x15, 0x69, 0x61, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x69, 0x61, 0x6d, 0x61, 0x6e, 0x61, 0x67,
	0x65, 0x72, 0x2e, 0x76, 0x31, 0x22, 0x9b, 0x01, 0x0a, 0x0b, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x4c, 0x0a, 0x0b, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73,
	0x69, 0x6f, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x69, 0x61, 0x6d,
	0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0b, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69,
	0x6f, 0x6e, 0x73, 0x1a, 0x3e, 0x0a, 0x10, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a,
	0x02, 0x38, 0x01, 0x22, 0x27, 0x0a, 0x0f, 0x55, 0x73, 0x65, 0x72, 0x73, 0x43, 0x68, 0x61, 0x6e,
	0x67, 0x65, 0x64, 0x4e, 0x74, 0x66, 0x12, 0x14, 0x0a, 0x05, 0x75, 0x73, 0x65, 0x72, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x05, 0x75, 0x73, 0x65, 0x72, 0x73, 0x42, 0x34, 0x5a, 0x32,
	0x67, 0x69, 0x74, 0x70, 0x63, 0x74, 0x2e, 0x65, 0x70, 0x61, 0x6d, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x65, 0x70, 0x6d, 0x64, 0x2d, 0x61, 0x65, 0x70, 0x72, 0x2f, 0x61, 0x6f, 0x73, 0x5f, 0x63, 0x6f,
	0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x69, 0x61, 0x6d, 0x61, 0x6e, 0x61, 0x67,
	0x65, 0x72, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_iamanagercommon_proto_rawDescOnce sync.Once
	file_iamanagercommon_proto_rawDescData = file_iamanagercommon_proto_rawDesc
)

func file_iamanagercommon_proto_rawDescGZIP() []byte {
	file_iamanagercommon_proto_rawDescOnce.Do(func() {
		file_iamanagercommon_proto_rawDescData = protoimpl.X.CompressGZIP(file_iamanagercommon_proto_rawDescData)
	})
	return file_iamanagercommon_proto_rawDescData
}

var file_iamanagercommon_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_iamanagercommon_proto_goTypes = []interface{}{
	(*Permissions)(nil),     // 0: iamanager.v1.Permissions
	(*UsersChangedNtf)(nil), // 1: iamanager.v1.UsersChangedNtf
	nil,                     // 2: iamanager.v1.Permissions.PermissionsEntry
}
var file_iamanagercommon_proto_depIdxs = []int32{
	2, // 0: iamanager.v1.Permissions.permissions:type_name -> iamanager.v1.Permissions.PermissionsEntry
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_iamanagercommon_proto_init() }
func file_iamanagercommon_proto_init() {
	if File_iamanagercommon_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_iamanagercommon_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Permissions); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_iamanagercommon_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UsersChangedNtf); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_iamanagercommon_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_iamanagercommon_proto_goTypes,
		DependencyIndexes: file_iamanagercommon_proto_depIdxs,
		MessageInfos:      file_iamanagercommon_proto_msgTypes,
	}.Build()
	File_iamanagercommon_proto = out.File
	file_iamanagercommon_proto_rawDesc = nil
	file_iamanagercommon_proto_goTypes = nil
	file_iamanagercommon_proto_depIdxs = nil
}

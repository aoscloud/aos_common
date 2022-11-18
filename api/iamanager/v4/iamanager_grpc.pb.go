// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.6.1
// source: iamanager/v4/iamanager.proto

package iamanager

import (
	context "context"
	empty "github.com/golang/protobuf/ptypes/empty"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// IAMPublicServiceClient is the client API for IAMPublicService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type IAMPublicServiceClient interface {
	GetAPIVersion(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*APIVersion, error)
	GetNodeID(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*NodeID, error)
	GetCert(ctx context.Context, in *GetCertRequest, opts ...grpc.CallOption) (*GetCertResponse, error)
}

type iAMPublicServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewIAMPublicServiceClient(cc grpc.ClientConnInterface) IAMPublicServiceClient {
	return &iAMPublicServiceClient{cc}
}

func (c *iAMPublicServiceClient) GetAPIVersion(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*APIVersion, error) {
	out := new(APIVersion)
	err := c.cc.Invoke(ctx, "/iamanager.v4.IAMPublicService/GetAPIVersion", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iAMPublicServiceClient) GetNodeID(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*NodeID, error) {
	out := new(NodeID)
	err := c.cc.Invoke(ctx, "/iamanager.v4.IAMPublicService/GetNodeID", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iAMPublicServiceClient) GetCert(ctx context.Context, in *GetCertRequest, opts ...grpc.CallOption) (*GetCertResponse, error) {
	out := new(GetCertResponse)
	err := c.cc.Invoke(ctx, "/iamanager.v4.IAMPublicService/GetCert", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// IAMPublicServiceServer is the server API for IAMPublicService service.
// All implementations must embed UnimplementedIAMPublicServiceServer
// for forward compatibility
type IAMPublicServiceServer interface {
	GetAPIVersion(context.Context, *empty.Empty) (*APIVersion, error)
	GetNodeID(context.Context, *empty.Empty) (*NodeID, error)
	GetCert(context.Context, *GetCertRequest) (*GetCertResponse, error)
	mustEmbedUnimplementedIAMPublicServiceServer()
}

// UnimplementedIAMPublicServiceServer must be embedded to have forward compatible implementations.
type UnimplementedIAMPublicServiceServer struct {
}

func (UnimplementedIAMPublicServiceServer) GetAPIVersion(context.Context, *empty.Empty) (*APIVersion, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAPIVersion not implemented")
}
func (UnimplementedIAMPublicServiceServer) GetNodeID(context.Context, *empty.Empty) (*NodeID, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetNodeID not implemented")
}
func (UnimplementedIAMPublicServiceServer) GetCert(context.Context, *GetCertRequest) (*GetCertResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCert not implemented")
}
func (UnimplementedIAMPublicServiceServer) mustEmbedUnimplementedIAMPublicServiceServer() {}

// UnsafeIAMPublicServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to IAMPublicServiceServer will
// result in compilation errors.
type UnsafeIAMPublicServiceServer interface {
	mustEmbedUnimplementedIAMPublicServiceServer()
}

func RegisterIAMPublicServiceServer(s grpc.ServiceRegistrar, srv IAMPublicServiceServer) {
	s.RegisterService(&IAMPublicService_ServiceDesc, srv)
}

func _IAMPublicService_GetAPIVersion_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(empty.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMPublicServiceServer).GetAPIVersion(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/iamanager.v4.IAMPublicService/GetAPIVersion",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMPublicServiceServer).GetAPIVersion(ctx, req.(*empty.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _IAMPublicService_GetNodeID_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(empty.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMPublicServiceServer).GetNodeID(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/iamanager.v4.IAMPublicService/GetNodeID",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMPublicServiceServer).GetNodeID(ctx, req.(*empty.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _IAMPublicService_GetCert_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetCertRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMPublicServiceServer).GetCert(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/iamanager.v4.IAMPublicService/GetCert",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMPublicServiceServer).GetCert(ctx, req.(*GetCertRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// IAMPublicService_ServiceDesc is the grpc.ServiceDesc for IAMPublicService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var IAMPublicService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "iamanager.v4.IAMPublicService",
	HandlerType: (*IAMPublicServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetAPIVersion",
			Handler:    _IAMPublicService_GetAPIVersion_Handler,
		},
		{
			MethodName: "GetNodeID",
			Handler:    _IAMPublicService_GetNodeID_Handler,
		},
		{
			MethodName: "GetCert",
			Handler:    _IAMPublicService_GetCert_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "iamanager/v4/iamanager.proto",
}

// IAMPublicIdentityServiceClient is the client API for IAMPublicIdentityService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type IAMPublicIdentityServiceClient interface {
	GetSystemInfo(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*SystemInfo, error)
	GetSubjects(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*Subjects, error)
	SubscribeSubjectsChanged(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (IAMPublicIdentityService_SubscribeSubjectsChangedClient, error)
}

type iAMPublicIdentityServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewIAMPublicIdentityServiceClient(cc grpc.ClientConnInterface) IAMPublicIdentityServiceClient {
	return &iAMPublicIdentityServiceClient{cc}
}

func (c *iAMPublicIdentityServiceClient) GetSystemInfo(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*SystemInfo, error) {
	out := new(SystemInfo)
	err := c.cc.Invoke(ctx, "/iamanager.v4.IAMPublicIdentityService/GetSystemInfo", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iAMPublicIdentityServiceClient) GetSubjects(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*Subjects, error) {
	out := new(Subjects)
	err := c.cc.Invoke(ctx, "/iamanager.v4.IAMPublicIdentityService/GetSubjects", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iAMPublicIdentityServiceClient) SubscribeSubjectsChanged(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (IAMPublicIdentityService_SubscribeSubjectsChangedClient, error) {
	stream, err := c.cc.NewStream(ctx, &IAMPublicIdentityService_ServiceDesc.Streams[0], "/iamanager.v4.IAMPublicIdentityService/SubscribeSubjectsChanged", opts...)
	if err != nil {
		return nil, err
	}
	x := &iAMPublicIdentityServiceSubscribeSubjectsChangedClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type IAMPublicIdentityService_SubscribeSubjectsChangedClient interface {
	Recv() (*Subjects, error)
	grpc.ClientStream
}

type iAMPublicIdentityServiceSubscribeSubjectsChangedClient struct {
	grpc.ClientStream
}

func (x *iAMPublicIdentityServiceSubscribeSubjectsChangedClient) Recv() (*Subjects, error) {
	m := new(Subjects)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// IAMPublicIdentityServiceServer is the server API for IAMPublicIdentityService service.
// All implementations must embed UnimplementedIAMPublicIdentityServiceServer
// for forward compatibility
type IAMPublicIdentityServiceServer interface {
	GetSystemInfo(context.Context, *empty.Empty) (*SystemInfo, error)
	GetSubjects(context.Context, *empty.Empty) (*Subjects, error)
	SubscribeSubjectsChanged(*empty.Empty, IAMPublicIdentityService_SubscribeSubjectsChangedServer) error
	mustEmbedUnimplementedIAMPublicIdentityServiceServer()
}

// UnimplementedIAMPublicIdentityServiceServer must be embedded to have forward compatible implementations.
type UnimplementedIAMPublicIdentityServiceServer struct {
}

func (UnimplementedIAMPublicIdentityServiceServer) GetSystemInfo(context.Context, *empty.Empty) (*SystemInfo, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSystemInfo not implemented")
}
func (UnimplementedIAMPublicIdentityServiceServer) GetSubjects(context.Context, *empty.Empty) (*Subjects, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSubjects not implemented")
}
func (UnimplementedIAMPublicIdentityServiceServer) SubscribeSubjectsChanged(*empty.Empty, IAMPublicIdentityService_SubscribeSubjectsChangedServer) error {
	return status.Errorf(codes.Unimplemented, "method SubscribeSubjectsChanged not implemented")
}
func (UnimplementedIAMPublicIdentityServiceServer) mustEmbedUnimplementedIAMPublicIdentityServiceServer() {
}

// UnsafeIAMPublicIdentityServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to IAMPublicIdentityServiceServer will
// result in compilation errors.
type UnsafeIAMPublicIdentityServiceServer interface {
	mustEmbedUnimplementedIAMPublicIdentityServiceServer()
}

func RegisterIAMPublicIdentityServiceServer(s grpc.ServiceRegistrar, srv IAMPublicIdentityServiceServer) {
	s.RegisterService(&IAMPublicIdentityService_ServiceDesc, srv)
}

func _IAMPublicIdentityService_GetSystemInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(empty.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMPublicIdentityServiceServer).GetSystemInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/iamanager.v4.IAMPublicIdentityService/GetSystemInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMPublicIdentityServiceServer).GetSystemInfo(ctx, req.(*empty.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _IAMPublicIdentityService_GetSubjects_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(empty.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMPublicIdentityServiceServer).GetSubjects(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/iamanager.v4.IAMPublicIdentityService/GetSubjects",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMPublicIdentityServiceServer).GetSubjects(ctx, req.(*empty.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _IAMPublicIdentityService_SubscribeSubjectsChanged_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(empty.Empty)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(IAMPublicIdentityServiceServer).SubscribeSubjectsChanged(m, &iAMPublicIdentityServiceSubscribeSubjectsChangedServer{stream})
}

type IAMPublicIdentityService_SubscribeSubjectsChangedServer interface {
	Send(*Subjects) error
	grpc.ServerStream
}

type iAMPublicIdentityServiceSubscribeSubjectsChangedServer struct {
	grpc.ServerStream
}

func (x *iAMPublicIdentityServiceSubscribeSubjectsChangedServer) Send(m *Subjects) error {
	return x.ServerStream.SendMsg(m)
}

// IAMPublicIdentityService_ServiceDesc is the grpc.ServiceDesc for IAMPublicIdentityService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var IAMPublicIdentityService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "iamanager.v4.IAMPublicIdentityService",
	HandlerType: (*IAMPublicIdentityServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetSystemInfo",
			Handler:    _IAMPublicIdentityService_GetSystemInfo_Handler,
		},
		{
			MethodName: "GetSubjects",
			Handler:    _IAMPublicIdentityService_GetSubjects_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "SubscribeSubjectsChanged",
			Handler:       _IAMPublicIdentityService_SubscribeSubjectsChanged_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "iamanager/v4/iamanager.proto",
}

// IAMPublicPermissionsServiceClient is the client API for IAMPublicPermissionsService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type IAMPublicPermissionsServiceClient interface {
	GetPermissions(ctx context.Context, in *PermissionsRequest, opts ...grpc.CallOption) (*PermissionsResponse, error)
}

type iAMPublicPermissionsServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewIAMPublicPermissionsServiceClient(cc grpc.ClientConnInterface) IAMPublicPermissionsServiceClient {
	return &iAMPublicPermissionsServiceClient{cc}
}

func (c *iAMPublicPermissionsServiceClient) GetPermissions(ctx context.Context, in *PermissionsRequest, opts ...grpc.CallOption) (*PermissionsResponse, error) {
	out := new(PermissionsResponse)
	err := c.cc.Invoke(ctx, "/iamanager.v4.IAMPublicPermissionsService/GetPermissions", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// IAMPublicPermissionsServiceServer is the server API for IAMPublicPermissionsService service.
// All implementations must embed UnimplementedIAMPublicPermissionsServiceServer
// for forward compatibility
type IAMPublicPermissionsServiceServer interface {
	GetPermissions(context.Context, *PermissionsRequest) (*PermissionsResponse, error)
	mustEmbedUnimplementedIAMPublicPermissionsServiceServer()
}

// UnimplementedIAMPublicPermissionsServiceServer must be embedded to have forward compatible implementations.
type UnimplementedIAMPublicPermissionsServiceServer struct {
}

func (UnimplementedIAMPublicPermissionsServiceServer) GetPermissions(context.Context, *PermissionsRequest) (*PermissionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPermissions not implemented")
}
func (UnimplementedIAMPublicPermissionsServiceServer) mustEmbedUnimplementedIAMPublicPermissionsServiceServer() {
}

// UnsafeIAMPublicPermissionsServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to IAMPublicPermissionsServiceServer will
// result in compilation errors.
type UnsafeIAMPublicPermissionsServiceServer interface {
	mustEmbedUnimplementedIAMPublicPermissionsServiceServer()
}

func RegisterIAMPublicPermissionsServiceServer(s grpc.ServiceRegistrar, srv IAMPublicPermissionsServiceServer) {
	s.RegisterService(&IAMPublicPermissionsService_ServiceDesc, srv)
}

func _IAMPublicPermissionsService_GetPermissions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PermissionsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMPublicPermissionsServiceServer).GetPermissions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/iamanager.v4.IAMPublicPermissionsService/GetPermissions",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMPublicPermissionsServiceServer).GetPermissions(ctx, req.(*PermissionsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// IAMPublicPermissionsService_ServiceDesc is the grpc.ServiceDesc for IAMPublicPermissionsService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var IAMPublicPermissionsService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "iamanager.v4.IAMPublicPermissionsService",
	HandlerType: (*IAMPublicPermissionsServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetPermissions",
			Handler:    _IAMPublicPermissionsService_GetPermissions_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "iamanager/v4/iamanager.proto",
}

// IAMProvisioningServiceClient is the client API for IAMProvisioningService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type IAMProvisioningServiceClient interface {
	GetAllNodeIDs(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*NodesID, error)
	GetCertTypes(ctx context.Context, in *GetCertTypesRequest, opts ...grpc.CallOption) (*CertTypes, error)
	SetOwner(ctx context.Context, in *SetOwnerRequest, opts ...grpc.CallOption) (*empty.Empty, error)
	Clear(ctx context.Context, in *ClearRequest, opts ...grpc.CallOption) (*empty.Empty, error)
	EncryptDisk(ctx context.Context, in *EncryptDiskRequest, opts ...grpc.CallOption) (*empty.Empty, error)
	FinishProvisioning(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*empty.Empty, error)
}

type iAMProvisioningServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewIAMProvisioningServiceClient(cc grpc.ClientConnInterface) IAMProvisioningServiceClient {
	return &iAMProvisioningServiceClient{cc}
}

func (c *iAMProvisioningServiceClient) GetAllNodeIDs(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*NodesID, error) {
	out := new(NodesID)
	err := c.cc.Invoke(ctx, "/iamanager.v4.IAMProvisioningService/GetAllNodeIDs", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iAMProvisioningServiceClient) GetCertTypes(ctx context.Context, in *GetCertTypesRequest, opts ...grpc.CallOption) (*CertTypes, error) {
	out := new(CertTypes)
	err := c.cc.Invoke(ctx, "/iamanager.v4.IAMProvisioningService/GetCertTypes", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iAMProvisioningServiceClient) SetOwner(ctx context.Context, in *SetOwnerRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/iamanager.v4.IAMProvisioningService/SetOwner", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iAMProvisioningServiceClient) Clear(ctx context.Context, in *ClearRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/iamanager.v4.IAMProvisioningService/Clear", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iAMProvisioningServiceClient) EncryptDisk(ctx context.Context, in *EncryptDiskRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/iamanager.v4.IAMProvisioningService/EncryptDisk", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iAMProvisioningServiceClient) FinishProvisioning(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/iamanager.v4.IAMProvisioningService/FinishProvisioning", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// IAMProvisioningServiceServer is the server API for IAMProvisioningService service.
// All implementations must embed UnimplementedIAMProvisioningServiceServer
// for forward compatibility
type IAMProvisioningServiceServer interface {
	GetAllNodeIDs(context.Context, *empty.Empty) (*NodesID, error)
	GetCertTypes(context.Context, *GetCertTypesRequest) (*CertTypes, error)
	SetOwner(context.Context, *SetOwnerRequest) (*empty.Empty, error)
	Clear(context.Context, *ClearRequest) (*empty.Empty, error)
	EncryptDisk(context.Context, *EncryptDiskRequest) (*empty.Empty, error)
	FinishProvisioning(context.Context, *empty.Empty) (*empty.Empty, error)
	mustEmbedUnimplementedIAMProvisioningServiceServer()
}

// UnimplementedIAMProvisioningServiceServer must be embedded to have forward compatible implementations.
type UnimplementedIAMProvisioningServiceServer struct {
}

func (UnimplementedIAMProvisioningServiceServer) GetAllNodeIDs(context.Context, *empty.Empty) (*NodesID, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAllNodeIDs not implemented")
}
func (UnimplementedIAMProvisioningServiceServer) GetCertTypes(context.Context, *GetCertTypesRequest) (*CertTypes, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCertTypes not implemented")
}
func (UnimplementedIAMProvisioningServiceServer) SetOwner(context.Context, *SetOwnerRequest) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetOwner not implemented")
}
func (UnimplementedIAMProvisioningServiceServer) Clear(context.Context, *ClearRequest) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Clear not implemented")
}
func (UnimplementedIAMProvisioningServiceServer) EncryptDisk(context.Context, *EncryptDiskRequest) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method EncryptDisk not implemented")
}
func (UnimplementedIAMProvisioningServiceServer) FinishProvisioning(context.Context, *empty.Empty) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FinishProvisioning not implemented")
}
func (UnimplementedIAMProvisioningServiceServer) mustEmbedUnimplementedIAMProvisioningServiceServer() {
}

// UnsafeIAMProvisioningServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to IAMProvisioningServiceServer will
// result in compilation errors.
type UnsafeIAMProvisioningServiceServer interface {
	mustEmbedUnimplementedIAMProvisioningServiceServer()
}

func RegisterIAMProvisioningServiceServer(s grpc.ServiceRegistrar, srv IAMProvisioningServiceServer) {
	s.RegisterService(&IAMProvisioningService_ServiceDesc, srv)
}

func _IAMProvisioningService_GetAllNodeIDs_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(empty.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMProvisioningServiceServer).GetAllNodeIDs(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/iamanager.v4.IAMProvisioningService/GetAllNodeIDs",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMProvisioningServiceServer).GetAllNodeIDs(ctx, req.(*empty.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _IAMProvisioningService_GetCertTypes_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetCertTypesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMProvisioningServiceServer).GetCertTypes(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/iamanager.v4.IAMProvisioningService/GetCertTypes",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMProvisioningServiceServer).GetCertTypes(ctx, req.(*GetCertTypesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IAMProvisioningService_SetOwner_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetOwnerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMProvisioningServiceServer).SetOwner(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/iamanager.v4.IAMProvisioningService/SetOwner",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMProvisioningServiceServer).SetOwner(ctx, req.(*SetOwnerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IAMProvisioningService_Clear_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ClearRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMProvisioningServiceServer).Clear(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/iamanager.v4.IAMProvisioningService/Clear",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMProvisioningServiceServer).Clear(ctx, req.(*ClearRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IAMProvisioningService_EncryptDisk_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EncryptDiskRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMProvisioningServiceServer).EncryptDisk(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/iamanager.v4.IAMProvisioningService/EncryptDisk",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMProvisioningServiceServer).EncryptDisk(ctx, req.(*EncryptDiskRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IAMProvisioningService_FinishProvisioning_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(empty.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMProvisioningServiceServer).FinishProvisioning(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/iamanager.v4.IAMProvisioningService/FinishProvisioning",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMProvisioningServiceServer).FinishProvisioning(ctx, req.(*empty.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

// IAMProvisioningService_ServiceDesc is the grpc.ServiceDesc for IAMProvisioningService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var IAMProvisioningService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "iamanager.v4.IAMProvisioningService",
	HandlerType: (*IAMProvisioningServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetAllNodeIDs",
			Handler:    _IAMProvisioningService_GetAllNodeIDs_Handler,
		},
		{
			MethodName: "GetCertTypes",
			Handler:    _IAMProvisioningService_GetCertTypes_Handler,
		},
		{
			MethodName: "SetOwner",
			Handler:    _IAMProvisioningService_SetOwner_Handler,
		},
		{
			MethodName: "Clear",
			Handler:    _IAMProvisioningService_Clear_Handler,
		},
		{
			MethodName: "EncryptDisk",
			Handler:    _IAMProvisioningService_EncryptDisk_Handler,
		},
		{
			MethodName: "FinishProvisioning",
			Handler:    _IAMProvisioningService_FinishProvisioning_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "iamanager/v4/iamanager.proto",
}

// IAMCertificateServiceClient is the client API for IAMCertificateService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type IAMCertificateServiceClient interface {
	CreateKey(ctx context.Context, in *CreateKeyRequest, opts ...grpc.CallOption) (*CreateKeyResponse, error)
	ApplyCert(ctx context.Context, in *ApplyCertRequest, opts ...grpc.CallOption) (*ApplyCertResponse, error)
}

type iAMCertificateServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewIAMCertificateServiceClient(cc grpc.ClientConnInterface) IAMCertificateServiceClient {
	return &iAMCertificateServiceClient{cc}
}

func (c *iAMCertificateServiceClient) CreateKey(ctx context.Context, in *CreateKeyRequest, opts ...grpc.CallOption) (*CreateKeyResponse, error) {
	out := new(CreateKeyResponse)
	err := c.cc.Invoke(ctx, "/iamanager.v4.IAMCertificateService/CreateKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iAMCertificateServiceClient) ApplyCert(ctx context.Context, in *ApplyCertRequest, opts ...grpc.CallOption) (*ApplyCertResponse, error) {
	out := new(ApplyCertResponse)
	err := c.cc.Invoke(ctx, "/iamanager.v4.IAMCertificateService/ApplyCert", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// IAMCertificateServiceServer is the server API for IAMCertificateService service.
// All implementations must embed UnimplementedIAMCertificateServiceServer
// for forward compatibility
type IAMCertificateServiceServer interface {
	CreateKey(context.Context, *CreateKeyRequest) (*CreateKeyResponse, error)
	ApplyCert(context.Context, *ApplyCertRequest) (*ApplyCertResponse, error)
	mustEmbedUnimplementedIAMCertificateServiceServer()
}

// UnimplementedIAMCertificateServiceServer must be embedded to have forward compatible implementations.
type UnimplementedIAMCertificateServiceServer struct {
}

func (UnimplementedIAMCertificateServiceServer) CreateKey(context.Context, *CreateKeyRequest) (*CreateKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateKey not implemented")
}
func (UnimplementedIAMCertificateServiceServer) ApplyCert(context.Context, *ApplyCertRequest) (*ApplyCertResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ApplyCert not implemented")
}
func (UnimplementedIAMCertificateServiceServer) mustEmbedUnimplementedIAMCertificateServiceServer() {}

// UnsafeIAMCertificateServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to IAMCertificateServiceServer will
// result in compilation errors.
type UnsafeIAMCertificateServiceServer interface {
	mustEmbedUnimplementedIAMCertificateServiceServer()
}

func RegisterIAMCertificateServiceServer(s grpc.ServiceRegistrar, srv IAMCertificateServiceServer) {
	s.RegisterService(&IAMCertificateService_ServiceDesc, srv)
}

func _IAMCertificateService_CreateKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMCertificateServiceServer).CreateKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/iamanager.v4.IAMCertificateService/CreateKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMCertificateServiceServer).CreateKey(ctx, req.(*CreateKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IAMCertificateService_ApplyCert_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ApplyCertRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMCertificateServiceServer).ApplyCert(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/iamanager.v4.IAMCertificateService/ApplyCert",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMCertificateServiceServer).ApplyCert(ctx, req.(*ApplyCertRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// IAMCertificateService_ServiceDesc is the grpc.ServiceDesc for IAMCertificateService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var IAMCertificateService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "iamanager.v4.IAMCertificateService",
	HandlerType: (*IAMCertificateServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateKey",
			Handler:    _IAMCertificateService_CreateKey_Handler,
		},
		{
			MethodName: "ApplyCert",
			Handler:    _IAMCertificateService_ApplyCert_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "iamanager/v4/iamanager.proto",
}

// IAMPermissionsServiceClient is the client API for IAMPermissionsService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type IAMPermissionsServiceClient interface {
	RegisterInstance(ctx context.Context, in *RegisterInstanceRequest, opts ...grpc.CallOption) (*RegisterInstanceResponse, error)
	UnregisterInstance(ctx context.Context, in *UnregisterInstanceRequest, opts ...grpc.CallOption) (*empty.Empty, error)
}

type iAMPermissionsServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewIAMPermissionsServiceClient(cc grpc.ClientConnInterface) IAMPermissionsServiceClient {
	return &iAMPermissionsServiceClient{cc}
}

func (c *iAMPermissionsServiceClient) RegisterInstance(ctx context.Context, in *RegisterInstanceRequest, opts ...grpc.CallOption) (*RegisterInstanceResponse, error) {
	out := new(RegisterInstanceResponse)
	err := c.cc.Invoke(ctx, "/iamanager.v4.IAMPermissionsService/RegisterInstance", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iAMPermissionsServiceClient) UnregisterInstance(ctx context.Context, in *UnregisterInstanceRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/iamanager.v4.IAMPermissionsService/UnregisterInstance", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// IAMPermissionsServiceServer is the server API for IAMPermissionsService service.
// All implementations must embed UnimplementedIAMPermissionsServiceServer
// for forward compatibility
type IAMPermissionsServiceServer interface {
	RegisterInstance(context.Context, *RegisterInstanceRequest) (*RegisterInstanceResponse, error)
	UnregisterInstance(context.Context, *UnregisterInstanceRequest) (*empty.Empty, error)
	mustEmbedUnimplementedIAMPermissionsServiceServer()
}

// UnimplementedIAMPermissionsServiceServer must be embedded to have forward compatible implementations.
type UnimplementedIAMPermissionsServiceServer struct {
}

func (UnimplementedIAMPermissionsServiceServer) RegisterInstance(context.Context, *RegisterInstanceRequest) (*RegisterInstanceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RegisterInstance not implemented")
}
func (UnimplementedIAMPermissionsServiceServer) UnregisterInstance(context.Context, *UnregisterInstanceRequest) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UnregisterInstance not implemented")
}
func (UnimplementedIAMPermissionsServiceServer) mustEmbedUnimplementedIAMPermissionsServiceServer() {}

// UnsafeIAMPermissionsServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to IAMPermissionsServiceServer will
// result in compilation errors.
type UnsafeIAMPermissionsServiceServer interface {
	mustEmbedUnimplementedIAMPermissionsServiceServer()
}

func RegisterIAMPermissionsServiceServer(s grpc.ServiceRegistrar, srv IAMPermissionsServiceServer) {
	s.RegisterService(&IAMPermissionsService_ServiceDesc, srv)
}

func _IAMPermissionsService_RegisterInstance_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterInstanceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMPermissionsServiceServer).RegisterInstance(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/iamanager.v4.IAMPermissionsService/RegisterInstance",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMPermissionsServiceServer).RegisterInstance(ctx, req.(*RegisterInstanceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IAMPermissionsService_UnregisterInstance_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UnregisterInstanceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMPermissionsServiceServer).UnregisterInstance(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/iamanager.v4.IAMPermissionsService/UnregisterInstance",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMPermissionsServiceServer).UnregisterInstance(ctx, req.(*UnregisterInstanceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// IAMPermissionsService_ServiceDesc is the grpc.ServiceDesc for IAMPermissionsService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var IAMPermissionsService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "iamanager.v4.IAMPermissionsService",
	HandlerType: (*IAMPermissionsServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "RegisterInstance",
			Handler:    _IAMPermissionsService_RegisterInstance_Handler,
		},
		{
			MethodName: "UnregisterInstance",
			Handler:    _IAMPermissionsService_UnregisterInstance_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "iamanager/v4/iamanager.proto",
}

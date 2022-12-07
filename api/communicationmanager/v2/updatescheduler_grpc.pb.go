// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.6.1
// source: communicationmanager/v2/updatescheduler.proto

package communicationmanager

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

// UpdateSchedulerServiceClient is the client API for UpdateSchedulerService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type UpdateSchedulerServiceClient interface {
	StartFOTAUpdate(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*empty.Empty, error)
	StartSOTAUpdate(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*empty.Empty, error)
	SubscribeNotifications(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (UpdateSchedulerService_SubscribeNotificationsClient, error)
}

type updateSchedulerServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewUpdateSchedulerServiceClient(cc grpc.ClientConnInterface) UpdateSchedulerServiceClient {
	return &updateSchedulerServiceClient{cc}
}

func (c *updateSchedulerServiceClient) StartFOTAUpdate(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/communicationmanager.v2.UpdateSchedulerService/StartFOTAUpdate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *updateSchedulerServiceClient) StartSOTAUpdate(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/communicationmanager.v2.UpdateSchedulerService/StartSOTAUpdate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *updateSchedulerServiceClient) SubscribeNotifications(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (UpdateSchedulerService_SubscribeNotificationsClient, error) {
	stream, err := c.cc.NewStream(ctx, &UpdateSchedulerService_ServiceDesc.Streams[0], "/communicationmanager.v2.UpdateSchedulerService/SubscribeNotifications", opts...)
	if err != nil {
		return nil, err
	}
	x := &updateSchedulerServiceSubscribeNotificationsClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type UpdateSchedulerService_SubscribeNotificationsClient interface {
	Recv() (*SchedulerNotifications, error)
	grpc.ClientStream
}

type updateSchedulerServiceSubscribeNotificationsClient struct {
	grpc.ClientStream
}

func (x *updateSchedulerServiceSubscribeNotificationsClient) Recv() (*SchedulerNotifications, error) {
	m := new(SchedulerNotifications)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// UpdateSchedulerServiceServer is the server API for UpdateSchedulerService service.
// All implementations must embed UnimplementedUpdateSchedulerServiceServer
// for forward compatibility
type UpdateSchedulerServiceServer interface {
	StartFOTAUpdate(context.Context, *empty.Empty) (*empty.Empty, error)
	StartSOTAUpdate(context.Context, *empty.Empty) (*empty.Empty, error)
	SubscribeNotifications(*empty.Empty, UpdateSchedulerService_SubscribeNotificationsServer) error
	mustEmbedUnimplementedUpdateSchedulerServiceServer()
}

// UnimplementedUpdateSchedulerServiceServer must be embedded to have forward compatible implementations.
type UnimplementedUpdateSchedulerServiceServer struct {
}

func (UnimplementedUpdateSchedulerServiceServer) StartFOTAUpdate(context.Context, *empty.Empty) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method StartFOTAUpdate not implemented")
}
func (UnimplementedUpdateSchedulerServiceServer) StartSOTAUpdate(context.Context, *empty.Empty) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method StartSOTAUpdate not implemented")
}
func (UnimplementedUpdateSchedulerServiceServer) SubscribeNotifications(*empty.Empty, UpdateSchedulerService_SubscribeNotificationsServer) error {
	return status.Errorf(codes.Unimplemented, "method SubscribeNotifications not implemented")
}
func (UnimplementedUpdateSchedulerServiceServer) mustEmbedUnimplementedUpdateSchedulerServiceServer() {
}

// UnsafeUpdateSchedulerServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to UpdateSchedulerServiceServer will
// result in compilation errors.
type UnsafeUpdateSchedulerServiceServer interface {
	mustEmbedUnimplementedUpdateSchedulerServiceServer()
}

func RegisterUpdateSchedulerServiceServer(s grpc.ServiceRegistrar, srv UpdateSchedulerServiceServer) {
	s.RegisterService(&UpdateSchedulerService_ServiceDesc, srv)
}

func _UpdateSchedulerService_StartFOTAUpdate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(empty.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UpdateSchedulerServiceServer).StartFOTAUpdate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/communicationmanager.v2.UpdateSchedulerService/StartFOTAUpdate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UpdateSchedulerServiceServer).StartFOTAUpdate(ctx, req.(*empty.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _UpdateSchedulerService_StartSOTAUpdate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(empty.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UpdateSchedulerServiceServer).StartSOTAUpdate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/communicationmanager.v2.UpdateSchedulerService/StartSOTAUpdate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UpdateSchedulerServiceServer).StartSOTAUpdate(ctx, req.(*empty.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _UpdateSchedulerService_SubscribeNotifications_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(empty.Empty)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(UpdateSchedulerServiceServer).SubscribeNotifications(m, &updateSchedulerServiceSubscribeNotificationsServer{stream})
}

type UpdateSchedulerService_SubscribeNotificationsServer interface {
	Send(*SchedulerNotifications) error
	grpc.ServerStream
}

type updateSchedulerServiceSubscribeNotificationsServer struct {
	grpc.ServerStream
}

func (x *updateSchedulerServiceSubscribeNotificationsServer) Send(m *SchedulerNotifications) error {
	return x.ServerStream.SendMsg(m)
}

// UpdateSchedulerService_ServiceDesc is the grpc.ServiceDesc for UpdateSchedulerService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var UpdateSchedulerService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "communicationmanager.v2.UpdateSchedulerService",
	HandlerType: (*UpdateSchedulerServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "StartFOTAUpdate",
			Handler:    _UpdateSchedulerService_StartFOTAUpdate_Handler,
		},
		{
			MethodName: "StartSOTAUpdate",
			Handler:    _UpdateSchedulerService_StartSOTAUpdate_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "SubscribeNotifications",
			Handler:       _UpdateSchedulerService_SubscribeNotifications_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "communicationmanager/v2/updatescheduler.proto",
}

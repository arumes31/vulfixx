package proto

import (
	reflect "reflect"
	sync "sync"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type CVERequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CveId string `protobuf:"bytes,1,opt,name=cve_id,json=cveId,proto3" json:"cve_id,omitempty"`
}

func (x *CVERequest) Reset() {
	*x = CVERequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cve_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CVERequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CVERequest) ProtoMessage() {}

func (x *CVERequest) ProtoReflect() protoreflect.Message {
	mi := &file_cve_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *CVERequest) GetCveId() string {
	if x != nil {
		return x.CveId
	}
	return ""
}

type CVEResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id            int32   `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	CveId         string  `protobuf:"bytes,2,opt,name=cve_id,json=cveId,proto3" json:"cve_id,omitempty"`
	Description   string  `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
	CvssScore     float64 `protobuf:"fixed64,4,opt,name=cvss_score,json=cvssScore,proto3" json:"cvss_score,omitempty"`
	PublishedDate string  `protobuf:"bytes,5,opt,name=published_date,json=publishedDate,proto3" json:"published_date,omitempty"`
}

func (x *CVEResponse) Reset() {
	*x = CVEResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cve_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CVEResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CVEResponse) ProtoMessage() {}

func (x *CVEResponse) ProtoReflect() protoreflect.Message {
	mi := &file_cve_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *CVEResponse) GetId() int32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *CVEResponse) GetCveId() string {
	if x != nil {
		return x.CveId
	}
	return ""
}

func (x *CVEResponse) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *CVEResponse) GetCvssScore() float64 {
	if x != nil {
		return x.CvssScore
	}
	return 0
}

func (x *CVEResponse) GetPublishedDate() string {
	if x != nil {
		return x.PublishedDate
	}
	return ""
}

var File_cve_proto protoreflect.FileDescriptor

var file_cve_proto_rawDesc = []byte{
	0x0a, 0x09, 0x63, 0x76, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x23, 0x0a, 0x0a, 0x43, 0x56, 0x45, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x15, 0x0a, 0x06, 0x63, 0x76, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x63, 0x76, 0x65, 0x49, 0x64, 0x22, 0x9c, 0x01, 0x0a, 0x0b, 0x43, 0x56, 0x45, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x05, 0x52, 0x02, 0x69, 0x64, 0x12, 0x15, 0x0a, 0x06, 0x63, 0x76, 0x65, 0x5f, 0x69,
	0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x63, 0x76, 0x65, 0x49, 0x64, 0x12, 0x20,
	0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x76, 0x73, 0x73, 0x5f, 0x73, 0x63, 0x6f, 0x72, 0x65, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x01, 0x52, 0x09, 0x63, 0x76, 0x73, 0x73, 0x53, 0x63, 0x6f, 0x72, 0x65, 0x12,
	0x25, 0x0a, 0x0e, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x65, 0x64, 0x5f, 0x64, 0x61, 0x74,
	0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x73, 0x68,
	0x65, 0x64, 0x44, 0x61, 0x74, 0x65, 0x32, 0x3d, 0x0a, 0x0a, 0x43, 0x56, 0x45, 0x53, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x12, 0x2f, 0x0a, 0x06, 0x47, 0x65, 0x74, 0x43, 0x56, 0x45, 0x12, 0x11,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x43, 0x56, 0x45, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x12, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x43, 0x56, 0x45, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x23, 0x5a, 0x21, 0x63, 0x76, 0x65, 0x2d, 0x74, 0x72, 0x61,
	0x63, 0x6b, 0x65, 0x72, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x77, 0x6f,
	0x72, 0x6b, 0x65, 0x72, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_cve_proto_rawDescOnce sync.Once
	file_cve_proto_rawDescData = file_cve_proto_rawDesc
)

func file_cve_proto_rawDescGZIP() []byte {
	file_cve_proto_rawDescOnce.Do(func() {
		file_cve_proto_rawDescData = protoimpl.X.CompressGZIP(file_cve_proto_rawDescData)
	})
	return file_cve_proto_rawDescData
}

var file_cve_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_cve_proto_goTypes = []any{
	(*CVERequest)(nil),  // 0: proto.CVERequest
	(*CVEResponse)(nil), // 1: proto.CVEResponse
}
var file_cve_proto_depIdxs = []int32{
	0, // 0: proto.CVEService.GetCVE:input_type -> proto.CVERequest
	1, // 1: proto.CVEService.GetCVE:output_type -> proto.CVEResponse
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_cve_proto_init() }
func file_cve_proto_init() {
	if File_cve_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_cve_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*CVERequest); i {
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
		file_cve_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*CVEResponse); i {
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
			RawDescriptor: file_cve_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_cve_proto_goTypes,
		DependencyIndexes: file_cve_proto_depIdxs,
		MessageInfos:      file_cve_proto_msgTypes,
	}.Build()
	File_cve_proto = out.File
	file_cve_proto_rawDesc = nil
	file_cve_proto_goTypes = nil
	file_cve_proto_depIdxs = nil
}

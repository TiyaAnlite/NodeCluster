# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: common.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0c\x63ommon.proto\"\xde\x01\n\x0b\x43lusterData\x12\x0f\n\x07node_id\x18\x01 \x01(\t\x12#\n\x04type\x18\x02 \x01(\x0e\x32\x15.ClusterData.DataType\x12+\n\x08\x63ompress\x18\x03 \x01(\x0e\x32\x19.ClusterData.CompressType\x12\x0c\n\x04\x64\x61ta\x18\x04 \x01(\x0c\"&\n\x08\x44\x61taType\x12\x0b\n\x07PAYLOAD\x10\x00\x12\r\n\tHEARTBEAT\x10\x01\"6\n\x0c\x43ompressType\x12\t\n\x05PLAIN\x10\x00\x12\x08\n\x04GZIP\x10\x01\x12\x08\n\x04ZLIB\x10\x02\x12\x07\n\x03LZ4\x10\x03\"\xde\x01\n\x0bPayloadData\x12#\n\x04type\x18\x01 \x01(\x0e\x32\x15.PayloadData.DataType\x12\x1f\n\x04\x61uth\x18\x02 \x01(\x0b\x32\x11.PayloadData.Auth\x12\x19\n\x07\x63ommand\x18\x03 \x01(\x0e\x32\x08.Command\x12\x0c\n\x04\x64\x61ta\x18\x04 \x01(\x0c\x1a=\n\x04\x41uth\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\x0c\n\x04node\x18\x02 \x01(\t\x12\x0c\n\x04time\x18\x03 \x01(\x05\x12\x0c\n\x04sign\x18\x04 \x01(\x0c\"!\n\x08\x44\x61taType\x12\x08\n\x04\x44\x41TA\x10\x00\x12\x0b\n\x07\x43OMMAND\x10\x01*)\n\x07\x43ommand\x12\x0c\n\x08REGISTER\x10\x00\x12\x10\n\x0cLIST_DEVICES\x10\x01\x62\x06proto3')

_COMMAND = DESCRIPTOR.enum_types_by_name['Command']
Command = enum_type_wrapper.EnumTypeWrapper(_COMMAND)
REGISTER = 0
LIST_DEVICES = 1


_CLUSTERDATA = DESCRIPTOR.message_types_by_name['ClusterData']
_PAYLOADDATA = DESCRIPTOR.message_types_by_name['PayloadData']
_PAYLOADDATA_AUTH = _PAYLOADDATA.nested_types_by_name['Auth']
_CLUSTERDATA_DATATYPE = _CLUSTERDATA.enum_types_by_name['DataType']
_CLUSTERDATA_COMPRESSTYPE = _CLUSTERDATA.enum_types_by_name['CompressType']
_PAYLOADDATA_DATATYPE = _PAYLOADDATA.enum_types_by_name['DataType']
ClusterData = _reflection.GeneratedProtocolMessageType('ClusterData', (_message.Message,), {
  'DESCRIPTOR' : _CLUSTERDATA,
  '__module__' : 'common_pb2'
  # @@protoc_insertion_point(class_scope:ClusterData)
  })
_sym_db.RegisterMessage(ClusterData)

PayloadData = _reflection.GeneratedProtocolMessageType('PayloadData', (_message.Message,), {

  'Auth' : _reflection.GeneratedProtocolMessageType('Auth', (_message.Message,), {
    'DESCRIPTOR' : _PAYLOADDATA_AUTH,
    '__module__' : 'common_pb2'
    # @@protoc_insertion_point(class_scope:PayloadData.Auth)
    })
  ,
  'DESCRIPTOR' : _PAYLOADDATA,
  '__module__' : 'common_pb2'
  # @@protoc_insertion_point(class_scope:PayloadData)
  })
_sym_db.RegisterMessage(PayloadData)
_sym_db.RegisterMessage(PayloadData.Auth)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _COMMAND._serialized_start=466
  _COMMAND._serialized_end=507
  _CLUSTERDATA._serialized_start=17
  _CLUSTERDATA._serialized_end=239
  _CLUSTERDATA_DATATYPE._serialized_start=145
  _CLUSTERDATA_DATATYPE._serialized_end=183
  _CLUSTERDATA_COMPRESSTYPE._serialized_start=185
  _CLUSTERDATA_COMPRESSTYPE._serialized_end=239
  _PAYLOADDATA._serialized_start=242
  _PAYLOADDATA._serialized_end=464
  _PAYLOADDATA_AUTH._serialized_start=368
  _PAYLOADDATA_AUTH._serialized_end=429
  _PAYLOADDATA_DATATYPE._serialized_start=431
  _PAYLOADDATA_DATATYPE._serialized_end=464
# @@protoc_insertion_point(module_scope)

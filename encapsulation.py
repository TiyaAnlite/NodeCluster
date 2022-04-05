import gzip
import zlib
import time
import random
import string
import base64
import lz4.block
import logging

from google.protobuf import json_format
from google.protobuf.message import DecodeError

from proto.common_pb2 import ClusterData as pb_ClusterData
from proto.common_pb2 import PayloadData as pb_PayloadData
from proto.common_pb2 import Command as enum_Command


class AuthToolkit:
    def get_key(self) -> str:
        raise RuntimeError("Method not implemented")

    def sign(self, data: bytes) -> bytes:
        raise RuntimeError("Method not implemented")

    def generate_node(self, digit=32) -> str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=digit))


class ServiceEvent:
    def __init__(self, node_id: str, auth: bool, command: str, service: str, data: bytes):
        self.node_id = node_id
        self.is_auth = auth
        self.command = command
        self.service = service
        self.data = data


class RegisteredService:
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    @staticmethod
    def parse_data(descriptor, data: bytes):
        descriptor.Clear()
        descriptor.ParseFromString(data)

    @staticmethod
    def descriptor_to_dict(descriptor) -> dict:
        return json_format.MessageToDict(descriptor)

    @staticmethod
    def dict_to_descriptor(dict_data: dict, descriptor):
        descriptor.Clear()
        json_format.ParseDict(dict_data, descriptor)

    @staticmethod
    def serialize_data(descriptor):
        return descriptor.SerializeToString()

    def on_command(self, event: ServiceEvent):
        pass

    def on_data(self, event: ServiceEvent):
        pass


class ClusterData:
    DEFAULT_COMPRESS_TYPE = pb_ClusterData.CompressType.ZLIB
    DEFAULT_COMPRESS_THRESHOLD = 128

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self._data = pb_ClusterData()
        self.node_id = ""
        self.heartbeat = False
        self.compress = 0
        self.payload = PayloadData(self.logger)

    def parse(self, data: bytes):
        try:
            self._data.Clear()
            self._data.ParseFromString(data)
            if not self._data.node_id:
                self.logger.error("ClusterData: node_id not set.")
                raise DecodeError()
            self.node_id = self._data.node_id
            self.compress = self._data.compress
            self.payload.node_id = self.node_id
            if self._data.type == pb_ClusterData.DataType.PAYLOAD:
                self.logger.debug("ClusterData: recv payload")
                if self._data.compress == pb_ClusterData.CompressType.PLAIN:
                    self.payload.parse(self._data.data)
                elif self._data.compress == pb_ClusterData.CompressType.GZIP:
                    self.payload.parse(gzip.decompress(self._data.data))
                elif self._data.compress == pb_ClusterData.CompressType.ZLIB:
                    self.payload.parse(zlib.decompress(self._data.data))
                elif self._data.compress == pb_ClusterData.CompressType.LZ4:
                    self.payload.parse(lz4.block.decompress(self._data.data))
                else:
                    self.logger.error("ClusterData: unsupported compress type")
                    raise DecodeError()
            elif self._data.type == pb_ClusterData.DataType.HEARTBEAT:
                self.logger.debug("ClusterData: recv heartbeat")
                self.heartbeat = True
            else:
                self.logger.error("ClusterData: unknown data type.")
                raise DecodeError()
        except DecodeError:
            self.logger.error("Illegal ClusterData received")

    def make_heartbeat(self, node_id: str):
        self.heartbeat = True
        self.node_id = node_id

    def make_payload(self, node_id: str) -> pb_PayloadData:
        self.heartbeat = False
        self.node_id = node_id
        return self.payload

    def serialize(self) -> bytes:
        self._data.Clear()
        self._data.node_id = self.node_id
        if self.heartbeat:
            self.logger.debug("ClusterData: send heartbeat")
            self._data.type = pb_ClusterData.DataType.HEARTBEAT
        else:
            self.logger.debug("ClusterData: send data")
            self._data.type = pb_ClusterData.DataType.PAYLOAD
            data = self.payload.serialize()
            if len(data) >= self.DEFAULT_COMPRESS_THRESHOLD:
                self._data.compress = self.DEFAULT_COMPRESS_TYPE
                if self.DEFAULT_COMPRESS_TYPE == pb_ClusterData.CompressType.PLAIN:
                    self._data.data = data
                elif self.DEFAULT_COMPRESS_TYPE == pb_ClusterData.CompressType.GZIP:
                    self._data.data = gzip.compress(data)
                elif self.DEFAULT_COMPRESS_TYPE == pb_ClusterData.CompressType.ZLIB:
                    self._data.data = zlib.compress(data)
                elif self.DEFAULT_COMPRESS_TYPE == pb_ClusterData.CompressType.LZ4:
                    self._data.data = lz4.block.compress(data)
                else:
                    raise RuntimeError("ClusterData: unknown compress type")
                self.logger.debug(f"ClusterData: compress payload {len(data)} -> {len(self._data.data)}")
            else:
                self._data.compress = pb_ClusterData.CompressType.PLAIN
                self._data.data = data
                self.logger.debug(f"ClusterData: payload {len(data)} bytes")
        return self._data.SerializeToString()


class PayloadData:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.node_id = ""
        self._data = pb_PayloadData()
        self.auth = dict()
        self.is_command = True
        self.toolkit = AuthToolkit()

    def set_toolkit(self, new_toolkit: AuthToolkit):
        self.toolkit = new_toolkit

    def parse(self, data: bytes):
        try:
            self._data.Clear()
            self._data.ParseFromString(data)
            self.auth = json_format.MessageToDict(self._data.auth)
            if self._data.type == pb_PayloadData.DataType.DATA:
                self.is_command = False
            elif self._data.type == pb_PayloadData.DataType.COMMAND:
                self.is_command = True
            else:
                self.logger.error("PayloadData: Unknown data type.")
                raise DecodeError()
        except DecodeError:
            self.logger.error("Illegal PayloadData received")

    def callback_payload(self, service_map: dict):
        """
        负载服务回调
        :param service_map: 服务注册表
        """
        service_name = enum_Command.Name(self._data.command) if self._data.command else self._data.service
        if service_name not in service_map:
            self.logger.warning(f"Unsupported service: {service_name}, req node: {self.node_id}")
            return
        event = ServiceEvent(self.node_id, self.check_auth(), enum_Command.Name(self._data.command), self._data.service,
                             self._data.data)
        if self.is_command:
            service_map[service_name].on_command(event)
        else:
            service_map[service_name].on_data(event)

    def _auth_sign(self, toolkit: AuthToolkit) -> bytes:
        data = "\n".join((self.auth["key"], self.auth["node"], str(self.auth["time"]), str(self._data.command))).encode(
            "utf-8")
        data += "\n".encode("utf-8") + self._data.data
        return toolkit.sign(data)

    def check_auth(self, toolkit: AuthToolkit = None) -> bool:
        """
        检查认证
        :param toolkit: 认证套件
        :return:
        """
        toolkit = toolkit if toolkit else self.toolkit
        if not self._data.auth.sign:
            return False
        if self._data.auth.key != toolkit.get_key():
            self.logger.warning(f"PayloadData: recv auth key {self._data.auth.key} mismatch")
            return False
        if self._data.auth.sign and self._data.auth.sign == self._auth_sign(toolkit):
            return True
        else:
            return False

    def make_command(self, command: int, data: bytes):
        """
        构建指令型负载
        :param command: 指令
        :param data: 指令数据
        """
        self._data.Clear()
        self._data.command = command
        self._data.data = data
        self.is_command = True
        self._data.type = pb_PayloadData.DataType.COMMAND

    def make_data(self, command: int, data: bytes):
        """
        构造数据型负载
        :param command: 数据对应指令
        :param data: 数据
        """
        self._data.Clear()
        self._data.command = command
        self._data.data = data
        self.is_command = False
        self._data.type = pb_PayloadData.DataType.DATA

    def auth_sign(self, toolkit: AuthToolkit = None):
        """
        对负载进行签名，必须在make过后调用
        :param toolkit: 认证套件
        """
        toolkit = toolkit if toolkit else self.toolkit
        self.auth["key"] = toolkit.get_key()
        self.auth["node"] = toolkit.generate_node()
        self.auth["time"] = int(time.time())
        self.auth["sign"] = base64.b64encode(self._auth_sign(toolkit)).decode()

    def get_command(self) -> int:
        return self._data.command

    def get_data(self) -> bytes:
        return self._data.data

    def serialize(self) -> bytes:
        json_format.ParseDict(self.auth, self._data.auth)
        return self._data.SerializeToString()

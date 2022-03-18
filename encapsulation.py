import gzip
import zlib
import time
import random
import string
import lz4.block
import logging

from google.protobuf import json_format
from google.protobuf.message import DecodeError

from proto.common_pb2 import ClusterData as pb_ClusterData
from proto.common_pb2 import PayloadData as pb_PayloadData


class AuthToolkit:
    def get_key(self) -> str:
        raise RuntimeError("Method not implemented")

    def sign(self, key: str, data: bytes) -> bytes:
        raise RuntimeError("Method not implemented")

    def generate_node(self, digit=32) -> str:
        return "".join(random.choices(string.ascii_uppercase + string.digits, k=digit))


class ClusterData:
    DEFAULT_COMPRESS_TYPE = pb_ClusterData.CompressType.ZLIB
    DEAULT_COMRESS_THRESHOLD = 128

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self._data = pb_ClusterData()
        self.node_id = ""
        self.heartbeat = False
        self.compress = 0
        self.payload = PayloadData(self.logger)

    def parse(self, data: bytes):
        try:
            self._data.ParseFromString(data)
            if not self._data.node_id:
                self.logger.error("ClusterData: node_id not set.")
                raise DecodeError()
            self.node_id = self._data.node_id
            self.compress = self._data.compress
            if self._data.type == pb_ClusterData.DataType.PAYLOAD:
                if self._data.compress == pb_ClusterData.CompressType.PLAIN:
                    self.payload.parse(self._data.data)
                elif self._data.compress == pb_ClusterData.CompressType.GZIP:
                    self.payload.parse(gzip.decompress(self._data.data))
                elif self._data.compress == pb_ClusterData.CompressType.ZLIB:
                    self.payload.parse(zlib.decompress(self._data.data))
                elif self._data.compress == pb_ClusterData.CompressType.LZ4:
                    self.payload.parse(lz4.block.decompress(self._data.data))
                else:
                    self.logger.error("ClusterData: not supported compress type")
            elif self._data.type == pb_ClusterData.DataType.HEARTBEAT:
                self.heartbeat = True
            else:
                self.logger.error("ClusterData: unknown data type.")
                raise DecodeError()
        except DecodeError:
            self.logger.error("Illegal ClusterData received")

    def make_heartbeat(self):
        self.heartbeat = True

    def make_payload(self, node_id: str):
        self.heartbeat = False
        self.node_id = node_id

    def serialize(self) -> bytes:
        self._data.Clear()
        self._data.node_id = self.node_id
        if self.heartbeat:
            self._data.type = pb_ClusterData.DataType.HEARTBEAT
        else:
            self._data.type = pb_ClusterData.DataType.PAYLOAD
            data = self.payload.serialize()
            if len(data) >= self.DEAULT_COMRESS_THRESHOLD:
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
                self._data.compress = pb_ClusterData.CompressType.PLAIN
                self._data.data = data
        return self._data.SerializeToString()


class PayloadData:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self._data = pb_PayloadData()
        self.auth = dict()
        self.command = True
        self.data = b''

    def parse(self, data: bytes):
        try:
            self._data.ParseFromString(data)
            self.auth = json_format.MessageToDict(self._data.auth)
            if self._data.type == pb_PayloadData.DataType.DATA:
                self.command = False
            elif self._data.type == pb_PayloadData.DataType.COMMAND:
                self.command = True
            else:
                self.logger.error("PayloadData: Unknown data type.")
                raise DecodeError()
        except DecodeError:
            self.logger.error("Illegal PayloadData received")

    def _auth_sign(self, toolkit: AuthToolkit) -> bytes:
        data = self.auth["key"] + self.auth["node"] + self.auth[
            "time"] + self._data.command.SerializeToString() + self.data
        return toolkit.sign(data)

    def check_auth(self, toolkit: AuthToolkit) -> bool:
        if self._data.auth.sign and self._data.auth.sign == self._auth_sign(toolkit):
            return True
        else:
            return False

    def make_command(self, command: int, data: bytes):
        self._data.command = command  # Command字段提前写入
        self.data = data
        self.command = True

    def make_data(self, command: int, data: bytes):
        self._data.command = command  # Command字段提前写入
        self.data = data
        self.command = False

    def auth_sign(self, toolkit: AuthToolkit):
        self.auth["key"] = toolkit.get_key()
        self.auth["node"] = toolkit.generate_node()
        self.auth["time"] = int(time.time())
        self.auth["sign"] = self._auth_sign()

    def serialize(self) -> bytes:
        self._data.Clear()
        self._data.type = pb_PayloadData.DataType.COMMAND if self.command else pb_PayloadData.DataType.DATA
        self._data.auth = json_format.ParseDict(self.auth)
        self._data.payload = self.data
        return self._data.SerializeToString()

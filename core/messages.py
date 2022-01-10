from enum import Enum
from struct import pack

from core.binary_stream import BinaryStream


class MessageID:
    NONE = -1
    HELO = 0xd


class RpcMessage:
    MESSAGE_ID = MessageID.NONE

    def __init__(self):
        # only RpcMessage data is written to stream. Length
        self.stream = BinaryStream()

    def make_packet(self):
        data = self.stream.read_all_reset()

        packet = pack('>I', len(data))
        packet += pack('>B', self.MESSAGE_ID)
        packet += data

        return packet


class HeloMessage(RpcMessage):

    def __init__(self, protocol_version, hexrays_license: bytes, hexrays_id, watermark):
        super().__init__()
        
        self.MESSAGE_ID = MessageID.HELO

        self.proto_version = 2
        self.license = hexrays_license
        self.id = hexrays_id
        self.watermark = watermark
        self.field_0x32 = 0

    def encode(self):
        self.stream.write_dd(self.proto_version)
        self.stream.write_string(self.license, 'ascii')  # bytes
        self.stream.write_lu32(self.id)
        self.stream.write_lu16(self.watermark)
        self.stream.write_ubyte(self.field_0x32)

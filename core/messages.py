from enum import Enum
from struct import pack

from core.binary_stream import BinaryStream
from core.ida_types import func_sig_t


class MessageID:
    NONE = -1
    HELO = 0xD
    PULL_MD = 0xE


class RpcMessage:
    MESSAGE_ID = MessageID.NONE

    def __init__(self):
        # only RpcMessage data is written to stream.
        self.stream = BinaryStream()

    def make_packet(self):
        data = self.stream.read_all_reset()

        packet = pack('>I', len(data))
        packet += pack('>B', self.MESSAGE_ID)
        packet += data

        return packet


class HeloMessage(RpcMessage):

    MESSAGE_ID = MessageID.HELO

    def __init__(self, protocol_version, hexrays_license: bytes, hexrays_id, watermark):
        super().__init__()

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


class PullMD(RpcMessage):
    
    MESSAGE_ID = MessageID.PULL_MD
    
    def __init__(self, flags, md_keys, func_signatures):
        super().__init__()

        self.flags = flags
        self.md_keys = md_keys
        self.func_signatures = func_signatures

    def encode(self):
        self.stream.write_dd(self.flags)

        self.stream.write_dd(len(self.md_keys))
        for md_key in self.md_keys:
            self.stream.write_dd(md_key)

        self.stream.write_dd(len(self.func_signatures))
        for func_sig in self.func_signatures:
            signature = func_sig_t(func_sig)
            signature.encode()
            self.stream.write(signature.bytes())

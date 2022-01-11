from struct import pack, unpack
from io import BytesIO


class BinaryStream:

    def __init__(self, data: bytes = b''):
        self.data = BytesIO(data)

    def write_dd(self, num):
        if not isinstance(num, int):
            raise Exception("value is not an integer")
        if num < 0:
            raise Exception("cannot build from negative number: %r" % (num,))
        if num > 0xFFFFFFFF:
            raise Exception(
                "cannot build from number above integer range: %r" % (num,))
        x = num

        if (x > 0x1FFFFFFF):
            x |= 0xFF00000000
            nbytes = 5
        elif (x > 0x3FFF):
            x |= 0xC0000000
            nbytes = 4
        elif (x > 0x7F):
            x |= 0x8000
            nbytes = 2
        else:
            nbytes = 1

        for i in range(nbytes, 0, -1):
            shifted_num = (x >> (8*(i-1))) & 0xFF
            self.write_ubyte(shifted_num)

    def write_string(self, string, encoding='ascii'):
        if isinstance(string, bytes):
            self.write_dd(len(string))
            self.write(string)
        else:
            encoded = string.encode(encoding)
            self.write_dd(len(encoded))
            self.write(encoded)

    def write_vbuff(self, data: bytes):
        self.write_dd(len(data))
        self.write(data)

    def write(self, data: bytes):
        self.data.write(data)

    def write_byte(self, i8):
        buff = pack("!b", i8)
        self.data.write(buff)

    def write_ubyte(self, i8):
        buff = pack('!B', i8)
        self.data.write(buff)

    def write_16(self, i16):
        buff = pack("!h", i16)
        self.data.write(buff)

    def write_32(self, i32):
        buff = pack("!i", i32)
        self.data.write(buff)

    def write_64(self, i64):
        buff = pack("!q", i64)
        self.data.write(buff)

    def write_l16(self, i16):
        buff = pack("<h", i16)
        self.data.write(buff)

    def write_l32(self, i32):
        buff = pack("<i", i32)
        self.data.write(buff)

    def write_l64(self, i64):
        buff = pack("<q", i64)
        self.data.write(buff)

    def write_u16(self, i16):
        buff = pack("!H", i16)
        self.data.write(buff)

    def write_u32(self, i32):
        buff = pack("!I", i32)
        self.data.write(buff)

    def write_u64(self, i64):
        buff = pack("!Q", i64)
        self.data.write(buff)

    def write_lu16(self, i16):
        buff = pack("<H", i16)
        self.data.write(buff)

    def write_lu32(self, i32):
        buff = pack("<I", i32)
        self.data.write(buff)

    def write_lu64(self, i64):
        buff = pack("<Q", i64)
        self.data.write(buff)

    def read_l16(self):
        buff = self.data.read(2)
        val, = unpack('<h', buff)
        return val

    def read_l32(self):
        buff = self.data.read(4)
        val, = unpack('<i', buff)
        return val

    def read_l64(self):
        buff = self.data.read(8)
        val, = unpack('<q', buff)
        return val

    def read_byte(self):
        buff = self.data.read(1)
        val, = unpack('!b', buff)
        return val

    def read_16(self):
        buff = self.data.read(2)
        val, = unpack('!h', buff)
        return val

    def read_32(self):
        buff = self.data.read(4)
        val, = unpack('!i', buff)
        return val

    def read_64(self):
        buff = self.data.read(8)
        val, = unpack('!q', buff)
        return val

    def read_all_reset(self):
        self.data.seek(0)
        return self.data.read()

    def sizeof(self):
        return self.data.getbuffer().nbytes

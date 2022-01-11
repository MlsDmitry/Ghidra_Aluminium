from core.binary_stream import BinaryStream


class ida_type:
    def __init__(self):
        self.stream = BinaryStream()

    def bytes(self):
        return self.stream.read_all_reset()


class func_sig_t(ida_type):
    def __init__(self, signature):
        super().__init__()
        self.version = 1
        self.signature: bytes = signature

    def encode(self):
        self.stream.write_dd(self.version)
        self.stream.write_vbuff(self.signature)

import socket
import construct as con
from construct import (
    Nibble, Byte, Bytes, Int8ub, Int16ub, Int16ul, Int16sb, Int32ub, Int32ul, Int64ub,
    CString, Hex,
    BitStruct, Struct, Array, Const, Rebuild, len_, this, FormatField,
    byte2int, int2byte, stream_read, stream_write, Construct, singleton, IntegerError, integertypes,
    Container,
    )
from construct.core import BitsInteger

IDA_PROTOCOLE_VERSION = 2

#######################################
#
# Construct adapters
#
# Each adapter handles (de)serialization of variable length integer
#######################################

@singleton
class IdaVarInt16(Construct):
    r"""
    construct adapter that handles (de)serialization of variable length int16 (see pack_dw/unpack_dw in IDA API)
    """

    def _parse(self, stream, context, path):
        b = byte2int(stream_read(stream, 1, path))
        extrabytes, mask = [
            # lookup table
            [0, 0xff], # (0b0xxxxxxx)
            [0, 0xff], # (0b0xxxxxxx)
            [1, 0x7f], # 0x80 (0b10xxxxxx)
            [2, 0x00]  # 0xC0 (0b11xxxxxx)
        ][b >> 6]

        num = b & mask
        for _ in range(extrabytes):
            num = (num << 8) + byte2int(stream_read(stream, 1, path))

        return num

    def _build(self, obj, stream, context, path):
        if not isinstance(obj, integertypes):
            raise IntegerError("value is not an integer", path=path)
        if obj < 0:
            raise IntegerError("cannot build from negative number: %r" % (obj,), path=path)
        if obj > 0xFFFF:
            raise IntegerError("cannot build from number above short range: %r" % (obj,), path=path)

        x = obj

        if (x > 0x3FFF):
            x |= 0xFF0000
            nbytes = 3
        elif (x > 0x7F):
            x |= 0x8000
            nbytes = 2
        else:
            nbytes = 1

        for i in range(nbytes, 0, -1):
            stream_write(stream, int2byte((x >> (8*(i-1))) & 0xFF), 1, path)

        return obj

@singleton
class IdaVarInt32(Construct):
    r"""
    construct adapter that handles (de)serialization of variable length int32 (see pack_dd/unpack_dd in IDA API)
    """

    def _parse(self, stream, context, path):
        b = byte2int(stream_read(stream, 1, path))
        extrabytes, mask = [
            [0, 0xff], [0, 0xff], [0, 0xff], [0, 0xff], # (0b0..xxxxx)
            [1, 0x7f], [1, 0x7f], # 0x80 (0b10.xxxxx)
            [3, 0x3f], # 0xC0 (0b110xxxxx)
            [4, 0x00]  # 0xE0 (0b111xxxxx)
        ][b>>5]

        num = b & mask
        for _ in range(extrabytes):
            num = (num << 8) + byte2int(stream_read(stream, 1, path))

        return num


    def _build(self, obj, stream, context, path):
        if not isinstance(obj, integertypes):
            raise IntegerError("value is not an integer", path=path)
        if obj < 0:
            raise IntegerError("cannot build from negative number: %r" % (obj,), path=path)
        if obj > 0xFFFFFFFF:
            raise IntegerError("cannot build from number above integer range: %r" % (obj,), path=path)
        x = obj

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
            stream_write(stream, int2byte((x >> (8*(i-1))) & 0xFF), 1, path)

        return obj

@singleton
class IdaVarInt64(Construct):
    """
    construct adapter that handles (de)serialization of variable length int64 (see pack_dq/unpack_dq in IDA API)
    """

    def _parse(self, stream, context, path):
        low = IdaVarInt32._parse(stream, context, path)
        high = IdaVarInt32._parse(stream, context, path)
        num = (high << 32) | low
        return num

    def _build(self, obj, stream, context, path):
        if not isinstance(obj, integertypes):
            raise IntegerError("value is not an integer", path=path)
        if obj < 0:
            raise IntegerError("cannot build from negative number: %r" % (obj,), path=path)
        if obj > 0xFFFFFFFFFFFFFFFF:
            raise IntegerError("cannot build from number above short range: %r" % (obj,), path=path)

        low = obj & 0xFFFFFFFF
        IdaVarInt32._build(low, stream, context, path)
        high = obj >> 32
        IdaVarInt32._build(high, stream, context, path)

        return obj




#######################################
#
# Basic types & helpers
#
#######################################

# String prefixed with a variable int size
VarString = con.PascalString(IdaVarInt32, "utf8")
# Bytes buffer prefixed with a variable int size
VarBuff = con.Prefixed(IdaVarInt32, con.GreedyBytes)
# IDA typedefs
ea_t = asize_t = adiff_t = con.ExprAdapter(IdaVarInt64, con.obj_-1, con.obj_+1)

# "template" for defining object list, prefixed with a variable int size
def ObjectList(obj):
    return con.PrefixedArray(IdaVarInt32, obj)


#######################################
#
# Lumina types
#
#######################################

# function signature
func_sig_t = con.Struct(
    "version" / Const(1, IdaVarInt32),  # protocol version (con.Default: 1)
    "signature" / VarBuff               # signature buffer
    )

# a.k.a func_info_t
func_metadata = con.Struct(
    "func_name" / CString("utf8"),      # function name
    "func_size" / IdaVarInt32,          # function size in bytes
    "serialized_data" / VarBuff         # metadata
    )

# extended func_metadata
func_info_t = con.Struct(
    "metadata" / func_metadata,                   #
    "popularity" / con.Default(IdaVarInt32, 0),   # unknown
    )

func_md_t = con.Struct(
    "metadata" / func_metadata,
    "signature" / func_sig_t
    )

# same as func_md_t with extra (unknown) field
func_md2_t = con.Struct(
    "metadata" / func_metadata,
    "signature" / func_sig_t,
    "field_0x58" / Hex(Const(0, IdaVarInt32)),
    )

#######################################
#
# Lumina message types
#
#######################################

RPC_TYPE = con.Enum(Byte,
    RPC_OK = 0xa,
    RPC_FAIL = 0xb,
    RPC_NOTIFY = 0xc,
    RPC_HELO = 0xd,
    PULL_MD = 0xe,
    PULL_MD_RESULT = 0xf,
    PUSH_MD = 0x10,
    PUSH_MD_RESULT = 0x11,
    # below messages are not implemented or not used by Lumina. Enjoy yourselves ;)
    GET_POP = 0x12,
    GET_POP_RESULT = 0x13,
    LIST_PEERS = 0x14,
    LIST_PEERS_RESULT = 0x15,
    KILL_SESSIONS = 0x16,
    KILL_SESSIONS_RESULT = 0x17,
    DEL_ENTRIES = 0x18,
    DEL_ENTRIES_RESULT = 0x19,
    SHOW_ENTRIES = 0x1a,
    SHOW_ENTRIES_RESULT = 0x1b,
    DUMP_MD = 0x1c,
    DUMP_MD_RESULT = 0x1d,
    CLEAN_DB = 0x1e,
    DEBUGCTL = 0x1f
)

RpcMessage_FAIL = con.Struct(
    "status" / IdaVarInt32,
    "message" / CString("utf-8"),                   # null terminated string
)

RpcMessage_HELO = con.Struct(
    "protocole" / con.Default(IdaVarInt32, IDA_PROTOCOLE_VERSION),
    "hexrays_licence" / VarBuff,                    # ida.key file content
    "hexrays_id" / Hex(Int32ul),                    # internal licence_info
    "watermark" / Hex(Int16ul),                     # internal licence_info
    "field_0x36" / IdaVarInt32,                     # always zero ?
)

RpcMessage_NOTIFY = con.Struct(
    "protocole" / con.Default(IdaVarInt32, IDA_PROTOCOLE_VERSION),
    "message" / CString("utf-8"),                   # null terminated string
)

RpcMessage_PULL_MD  = con.Struct(
    "flags" / IdaVarInt32,
    "ukn_list" / ObjectList(IdaVarInt32),           # list of IdaVarInt32
    "funcInfos" / ObjectList(func_sig_t)            # list of func_sig_t
)

RpcMessage_PULL_MD_RESULT = con.Struct(
    "found" / ObjectList(IdaVarInt32),              # list of boolean for each request in PULL_MD (1 if matching/found)
    "results" / ObjectList(func_info_t)             # list of func_info_t for each matching result
)

RpcMessage_PUSH_MD = con.Struct(
    "field_0x10" / IdaVarInt32,
    "idb_filepath" / CString("utf-8"),              # absolute file path of current idb
    "input_filepath" / CString("utf-8"),            # absolute file path of input file
    "input_md5" / Bytes(16),                        # input file md5
    "hostname" / CString("utf-8"),                  # machine name
    "funcInfos" / ObjectList(func_md_t),            # list of func_md_t to push
    "funcEas" / ObjectList(IdaVarInt64),            # absolute (!?) address of each pushed function
)


RpcMessage_PUSH_MD_RESULT = con.Struct(
    "resultsFlags" / ObjectList(IdaVarInt32),       # status for each function pushed
)



# Generic RPC message 'union'
RpcMessage = con.Switch(this.code,
        {
            RPC_TYPE.RPC_OK : con.Pass,
            RPC_TYPE.RPC_FAIL : RpcMessage_FAIL,
            RPC_TYPE.RPC_NOTIFY : RpcMessage_NOTIFY,
            RPC_TYPE.RPC_HELO : RpcMessage_HELO,
            RPC_TYPE.PULL_MD : RpcMessage_PULL_MD,
            RPC_TYPE.PULL_MD_RESULT : RpcMessage_PULL_MD_RESULT,
            RPC_TYPE.PUSH_MD : RpcMessage_PUSH_MD,
            RPC_TYPE.PUSH_MD_RESULT : RpcMessage_PUSH_MD_RESULT,
            #RPC_TYPE.GET_POP : RpcMessage_GET_POP,
            #RPC_TYPE.GET_POP_RESULT : RpcMessage_GET_POP_RESULT,
            #RPC_TYPE.LIST_PEERS : RpcMessage_LIST_PEERS,
            #RPC_TYPE.LIST_PEERS_RESULT : RpcMessage_LIST_PEERS_RESULT,
            #RPC_TYPE.KILL_SESSIONS : RpcMessage_KILL_SESSIONS,
            #RPC_TYPE.KILL_SESSIONS_RESULT : RpcMessage_KILL_SESSIONS_RESULT,
            #RPC_TYPE.DEL_ENTRIES : RpcMessage_DEL_ENTRIES,
            #RPC_TYPE.DEL_ENTRIES_RESULT : RpcMessage_DEL_ENTRIES_RESULT,
            #RPC_TYPE.SHOW_ENTRIES : RpcMessage_SHOW_ENTRIES,
            #RPC_TYPE.SHOW_ENTRIES_RESULT : RpcMessage_SHOW_ENTRIES_RESULT,
            #RPC_TYPE.DUMP_MD : RpcMessage_DUMP_MD,
            #RPC_TYPE.DUMP_MD_RESULT : RpcMessage_DUMP_MD_RESULT,
            #RPC_TYPE.CLEAN_DB : RpcMessage_CLEAN_DB,
            #RPC_TYPE.DEBUGCTL : RpcMessage_DEBUGCTL,
        },
        default = None
    )

# RPC packet common header
rpc_packet_t = con.Struct(
    "length" / Rebuild(Hex(Int32ub), len_(this.data)),
    "code" / RPC_TYPE,
    "data" / con.HexDump(Bytes(this.length))
    )

def rpc_message_build(code, **kwargs):
    """
    Build and serialize an RPC packet
    """
    data = RpcMessage.build(kwargs, code = code)

    return rpc_packet_t.build(Container(code = code,
        data = data)
    )

def rpc_message_parse(source):
    """
    Read and deserilize RPC message from a file-like object or socket)
    """
    if isinstance(source, str):
        # parse source as filename
        packet = rpc_packet_t.parse_stream(source)
    elif isinstance(source, bytes):
        # parse source as bytes
        packet = rpc_packet_t.parse(source)
    else:
        # parse source as file-like object
        if isinstance(source, socket.socket):
            # construct requires a file-like object with read/write methods:
            source = source.makefile(mode='rb')

        packet = rpc_packet_t.parse_stream(source)

    message = RpcMessage.parse(packet.data , code = packet.code)
    # Warning: parsing return a Container object wich hold a io.BytesIO to the socket
    # see https://github.com/construct/construct/issues/852
    return packet, message

#######################################
#
# Lumina type info
#
#######################################

TYPE_DECL_MODIF = con.Enum(IdaVarInt32,
    SIGNED = 0x10,
    UNSIGNED = 0x20,
    CONST = 0x40,
    VOLATILE = 0x80,
    POINTER = 0x0a00,
    __NORETURN = 0xaf01,
    __HIDDEN = 0xff41,
    __RETURN_PTR = 0xff42,
    __STRUCT_PTR = 0xff43,
    __ARRAY_PTR = 0xff48,
    )

# @singleton
# class Argument(Construct):
#     r"""
#     construct adapter that parses FUNC_DEF's arguments
#     """

#     def _parse(self, stream, context, path):
#         b = byte2int(stream_read(stream, 1, path))
        


#         return arg

#     def _build(self, obj, stream, context, path):
#         if not isinstance(obj, integertypes):
#             raise IntegerError("value is not an integer", path=path)
#         if obj < 0:
#             raise IntegerError("cannot build from negative number: %r" % (obj,), path=path)
#         if obj > 0xFFFF:
#             raise IntegerError("cannot build from number above short range: %r" % (obj,), path=path)

#         x = obj

#         if (x > 0x3FFF):
#             x |= 0xFF0000
#             nbytes = 3
#         elif (x > 0x7F):
#             x |= 0x8000
#             nbytes = 2
#         else:
#             nbytes = 1

#         for i in range(nbytes, 0, -1):
#             stream_write(stream, int2byte((x >> (8*(i-1))) & 0xFF), 1, path)

#         return obj

TYPE_DECL = con.Enum(IdaVarInt32,
    VOID         = 0x01,

    __INT8       = 0x02,
    CHAR         = 0x32,

    __INT16      = 0x03,

    __INT32      = 0x04,

    __INT64      = 0x05,

    __INT128     = 0x06,

    INT          = 0x07,
    __SEG        = 0x37,

    BOOL         = 0x08,
    _BOOL1       = 0x18,
    _BOOL2       = 0x28,
    _BOOL4       = 0x38,
    _BOOL8       = 0x48,
    
    FLOAT        = 0x09,
    DOUBLE       = 0x19,
    LONG_DOUBLE  = 0x29,
    SHORT_FLOAT  = 0x39, # conflicting with _TBYTE
    )

TYPE_CONST = con.Enum(IdaVarInt32,
    _WORD        = 0x10,
    _QWORD       = 0x20,
    _UNKNOWN     = 0x30,
    
    _BYTE        = 0x11,
    _DWORD       = 0x21,
    _OWORD       = 0x31,
        
    _TBYTE       = 0x39,
    )

FUNC_DEF_MODIF = con.Enum(IdaVarInt32, # TODO: make normal bitwise (it is cases for FUNC_DEF)
    __NEAR_FUNC      = 0x0C | (0x40 >> 2),
    __FAR_FUNC       = 0x0C | (0x80 >> 2),
    __INTERRUPT_FUNC = 0x0C | (0xC0 >> 2),
)

TINFO_TYPE = con.Enum(IdaVarInt32,
    FUNC_DEF         = 0x0C,

    # STRUCT   = 0x0d,
    )

CALLING_CONV = con.Enum(BitsInteger(4),
    __BAD_CC     =  0x0,
    __CDECL      =  0x3,
    __STDCALL    =  0x5,
    __PASCAL     =  0x6,
    __FASTCALL   =  0x7,
    __THISCALL   =  0x8,
    NOCALL       =  0x9,
    __USERCALL   =  0xD,
    __USERPURGE  =  0xE,
    __USERCALL_2 =  0xF,
    )

FLAGS = con.Struct(BitsInteger(4),
    "cc" / CALLING_CONV,
    "other" / Nibble,
    )

TInfo_FUNC = con.Struct(
    "flags" / Byte, # FLAGS,
    "return_type" / TYPE_DECL,
    "argc" / IdaVarInt32,
    # "argv" / Argument[this.argc - 1]
    )

TInfo = con.Switch(this.type,        
        {
            TINFO_TYPE.FUNC_DEF : TInfo_FUNC,
        },
        default = None
    )


#######################################
#
# Lumina metadata types
#
#######################################

MD_TYPE = con.Enum(IdaVarInt32,
    TYPE_INFO     = 0x1,
    NOP           = 0x2,
    CMNT_FUNC_REG = 0x3,
    CMNT_FUNC_REP = 0x4,
    CMNT_INST_REG = 0x5,
    CMNT_INST_REP = 0x6,
    CMNT_EXTRA    = 0x7,
    STACK_PTRS    = 0x8,
    FRAME_DESCR   = 0x9,
    INST_OPR_REP  = 0xA,


    # under construction
    # STRUCT_SHARE  = 0xFF,
)

MdMessage_TYPE_INFO = con.Struct(
    'unk' / Byte,
    'type' / TINFO_TYPE,
    )

# Generic MD message 'union'
MdMessage = con.Switch(this.cmd,
        {
            MD_TYPE.TYPE_INFO : MdMessage_TYPE_INFO,
            # MD_TYPE.NOP : RpcMessage_FAIL,
            # MD_TYPE.CMNT_FUNC_REG : RpcMessage_NOTIFY,
            # MD_TYPE.CMNT_FUNC_REP : RpcMessage_HELO,
            # MD_TYPE.CMNT_INST_REG : RpcMessage_PULL_MD,
            # MD_TYPE.CMNT_INST_REP : RpcMessage_PULL_MD_RESULT,
            # MD_TYPE.CMNT_EXTRA : RpcMessage_PUSH_MD,
            # MD_TYPE.STACK_PTRS : RpcMessage_PUSH_MD_RESULT,
            # MD_TYPE.FRAME_DESCR : RpcMessage_GET_POP,
            # MD_TYPE.INST_OPR_REP : RpcMessage_GET_POP_RESULT,
        
            # MD_TYPE.STRUCT_SHARE : 
        },
        default = None
    )

# MD packet common header
md_packet_t = con.Struct(
    "cmd" / MD_TYPE,
    "buf" / VarBuff
    )

def md_message_build(code, **kwargs):
    """
    Build and serialize an MD packet
    """
    data = RpcMessage.build(kwargs, code = code)

    return md_packet_t.build(Container(code = code,
        data = data)
    )

def md_message_parse(source):
    """
    Read and deserilize MD message from a file-like object or socket)
    """
    packet = None
    while packet == None or packet.cmd != 0:
        if isinstance(source, str):
            # parse source as filename
            packet = md_packet_t.parse_stream(source)
        elif isinstance(source, bytes):
            # parse source as bytes
            packet = md_packet_t.parse(source)
        else:
            # parse source as file-like object
            if isinstance(source, socket.socket):
                # construct requires a file-like object with read/write methods:
                source = source.makefile(mode='rb')

            packet = md_packet_t.parse_stream(source)

        print(packet)
        message = MdMessage.parse(packet.buf , cmd = packet.cmd)
        print(message)
        if message.type == TINFO_TYPE.FUNC_DEF:
            buf = packet.buf[2:]
            message = TInfo.parse(buf, type = message.type)
            print(message)

        break
    # # # Warning: parsing return a Container object wich hold a io.BytesIO to the socket
    # # # see https://github.com/construct/construct/issues/852
    # return packet, message
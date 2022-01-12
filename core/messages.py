import socket, ssl

from core.lumina_structs import rpc_message_parse, rpc_message_build, RPC_TYPE, SERVER_STUFF, func_md_t
  
    
def get_push_info( anonMode ): # TODO: add some random...
    return b"idb_path", b"input_path", b"HmmmmmmmmmmmmmLooooooooksLikeMD5", b"hostname"

class Interface():
    def __init__(self, logger):
        self.logger = logger

    def conn(self, addr, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((addr, port))

    def waitIda(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("localhost", 6379))
        s.listen(1)
        self.sock, address  = s.accept()

    def tlsOn(self, addr, cert_path):
        self.logger.info(f"TLS certificate path for {addr} is {cert_path}")
        if cert_path == "":
            exit()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cert_path)
        self.sock = context.wrap_socket(self.sock,
                                    server_side = False,
                                    server_hostname = addr)

    def sendMessage(self, code, **kwargs):
        data = rpc_message_build(code, **kwargs)
        self.logger.debug(f"sending RPC Packet (code = {code}, data={kwargs})")
        self.sock.send(data)

    def recvMessage(self):
        packet, message = rpc_message_parse(self.sock)
        self.logger.debug(f"got new RPC Packet (code = {packet.code}, data={message})")
        return packet, message

class Communication():
    def __init__(self, logger):
        self.logger = logger

    def push(self, metadatas):
        for server in SERVER_STUFF["servers"]:
            allow_to_push_there = server[2]
            if not allow_to_push_there:
                continue

            addr, port, is_official, use_tls, cert_path = server[0], server[1], server[3], server[4], server[5]
            sock = Interface(self.logger)
            sock.conn(addr, port)

            if use_tls == "ON":
                sock.tlsOn(addr, cert_path)

            license, id, watermark = b"", 0, 0
            if is_official:
                license, id, watermark = SERVER_STUFF["license"], SERVER_STUFF["id"], SERVER_STUFF["watermark"]
            
            self.sendMessage(RPC_TYPE.RPC_HELO, hexrays_licence = license, hexrays_id = id, watermark = watermark, field_0x36=0)
            packet, message = self.recvMessage()
            if packet.code != RPC_TYPE.RPC_OK:
                self.logger.info(packet.data)
                exit()
            
            idb_path, input_path, file_md5, hostname = get_push_info()

            # under construction
            # self.sendMessage(RPC_TYPE.PUSH_MD, field_0x10 = 0, idb_filepath = idb_path, input_filepath = input_path, input_md5 = file_md5, hostname = hostname, funcInfos = , funcEas = )
            # packet, message = self.recvMessage()
            # if packet.code != RPC_TYPE.PUSH_MD_RESULT:
            #     self.logger.info(f"Expected {RPC_TYPE.PUSH_MD_RESULT} but {packet.code}")
            #     exit()

            # return message.resultsFlags

    def pull(self, arch, funcs_scope):
        for server in SERVER_STUFF["servers"]:
            addr, port, is_official, use_tls, cert_path = server[0], server[1], server[3], server[4], server[5]
            sock = Interface(self.logger)
            sock.conn(addr, port)

            if use_tls == "ON":
                sock.tlsOn(addr, cert_path)

            license, id, watermark = b"", 0, 0
            if is_official:
                license, id, watermark = SERVER_STUFF["license"], SERVER_STUFF["id"], SERVER_STUFF["watermark"]
            
            self.sendMessage(RPC_TYPE.RPC_HELO, hexrays_licence = license, hexrays_id = id, watermark = watermark, field_0x36=0)
            packet, message = self.recvMessage()
            if packet.code != RPC_TYPE.RPC_OK:
                self.logger.info(f"Expected {RPC_TYPE.RPC_OK} but {packet.code}")
                exit()

            #
            # Get all signatures and download their metadata from server
            #

            download_scope = []
            positions = []
            for i in range(len(funcs_scope)):
                if funcs_scope[i].get("signature"):
                    download_scope.append(funcs_scope[i])
                    positions.append(i)

            self.sendMessage(RPC_TYPE.PULL_MD, flags = self.arch, ukn_list = {}, funcInfos = download_scope)
            packet, message = self.recvMessage()

            if packet.code != RPC_TYPE.PULL_MD_RESULT:
                self.logger.debug(message)
                exit()

            #
            # Replace signature by metadata if it was downloaded
            #

            i, j = 0, 0
            while( j != len([k for k in message.found if k == 0]) ):
                if message.found[i] == 0:           # 0 - founded;
                    funcs_scope[positions[i]] = message.results[j]
                    j += 1
                i += 1

        found = list()
        results = list()
        for i in range(len(funcs_scope)):
            if funcs_scope[i].get("metadata") != None:
                found.append(0)
                results.append(funcs_scope[i])
            else:
                found.append(1)
        return results, found

    def getIdaLicenseInfo(self):
        self.logger.info('Waiting IDA connection...')
        sock = Interface(self.logger)
        sock.waitIda()

        packet, message = sock.recvMessage() # TODO: add interruptable loading windows
        if packet.code != RPC_TYPE.RPC_HELO:
            self.logger.warning('Expected helo')
            return

        self.logger.info(f"License key: {message.hexrays_licence}")
        self.logger.info(f"Id: {message.hexrays_id}")
        self.logger.info(f"Watermark {message.watermark}")

        sock.sendMessage(RPC_TYPE.RPC_FAIL, status = 0x1337, message = 'Please ctrl+c & ctrl+v your license info to core.lumina_structs.SERVER_STUFF')

        
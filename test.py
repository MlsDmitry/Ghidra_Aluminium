import logging, sys
from core.messages import Communication
from core.lumina_structs import func_sig_t, func_md_t, md_message_parse

def main():
    # default log handler is stdout. You can add a FileHandler or any handler you want
    log_handler = logging.StreamHandler(sys.stdout)
    log_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger = logging.getLogger("lumina")
    logger.addHandler(log_handler)
    logger.setLevel(logging.INFO)

    comm = Communication(logger)
    # comm.getIdaLicenseInfo()

    md_message_parse(b'\x01\x0b\x01\x0cq\x05\x02\n\x03\x00\x03a1')

    # tmp = func_md_t.build( {"metadata": {"func_name": "test_func", "func_size": 1337, "serialized_data": b""}, "signature": {"signature": b"1337" * 8}} )
    # tmp_positions = [0]
    # comm.push([func_md_t.parse(tmp)], tmp_positions)

    # arch = 1 # 0 - 32bit; 1 - 64bit
    # tmp = func_sig_t.build( {"signature": b'1337' * 8} )
    # results, found = comm.pull(arch, [func_sig_t.parse(tmp)])

    # for i in range(len(found)):
    #     if found[i] == 0:
    #         logger.debug("Founded")
    
if __name__ == "__main__":
    main()
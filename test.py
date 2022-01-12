import logging, sys
from core.messages import Communication

def main():
    # default log handler is stdout. You can add a FileHandler or any handler you want
    log_handler = logging.StreamHandler(sys.stdout)
    log_handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
    logger = logging.getLogger("lumina")
    logger.addHandler(log_handler)
    logger.setLevel(logging.INFO)

    comm = Communication(logger)
    # comm.getIdaLicenseInfo()
    
if __name__ == "__main__":
    main()
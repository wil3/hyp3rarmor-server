import logging
from Queue import Queue
import os
import argparse
import sys
import logging.config
import yaml
from hyp3rarmor.server.firewall import GrantAccess, RevokeAccess
from hyp3rarmor.server.monitor import UniversalTokenNetMonitor,IPBoundTokenNetMonitor
from hyp3rarmor.server.provider import  FileExporter, TokenClock, TokenState
from hyp3rarmor.common.constants import *
from hyp3rarmor.common.exceptions import Hyp3rArmorConfigurationError, Hyp3rArmorError
from hyp3rarmor.common.config import config 

#FIXME minimize privelges

logger = logging.getLogger('hyp3rarmor')

def init_logging():
    log_config = os.path.join(HYP3RARMOR_ROOT, "conf/logging.yaml")
    if os.path.exists(log_config):
        with open(log_config, 'rt') as f:
            log_config = yaml.load(f.read())
        logging.config.dictConfig(log_config)
    else:
        raise Hyp3rArmorError("Cannot find log configuration file")

def init_dirs():

    if not os.path.exists(HYP3RARMOR_GEN_DIR):
            os.makedirs(HYP3RARMOR_GEN_DIR)

def check_config():

    #Check if the interface exists
    #Check if access port defined
    if not config.access_ports:
        raise Hyp3rArmorConfigurationError("Must specify at least one service port")

    #Check if the port is valid
    #TODO Make access port an array
    #for port in config.access_ports:
        if config.access_ports < 0 or config.access_ports > MAX_PORT_NUMBER: 
            raise Hyp3rArmorConfigurationError("Port not valid")

    #Check if the token size and minimum receive is valid
    if not config.minimum_receive or not config.token_size or config.minimum_receive > config.token_size:
        raise Hyp3rArmorConfigurationError("minimum_receive must be less than or equal to token_size")

    #Check if the defense is valid
    if not (config.defense == DEFENSE_IP or config.defense == DEFENSE_DN):
        raise Hyp3rArmorConfigurationError("Defense must be one of ip or dn")


    if not config.export and config.scope == SCOPE_UNIVERSAL:
        logger.warn("Using universal AT but without export")

def hyp3rarmor_main():

    init_logging()
    init_dirs()
    check_config()

    # The monitor produces IP addresses to allow access to the webserver
    # the authorizer consumes IP addresses in the queue to white list
    access_granting_q = Queue()

    monitor = None
    if config.scope == SCOPE_IP:
        monitor = IPBoundATNetMonitor()
        monitor.init(access_granting_q)

    elif config.scope == SCOPE_UNIVERSAL:
        token_state = TokenState() 
        monitor = UniversalTokenNetMonitor()
        monitor.init(access_granting_q, token_state)

        exporter = None
        if config.export:
            exporter = FileExporter()

        clock = TokenClock()
        clock.init(token_state, exporter)
        clock.start()

    grant = GrantAccess()
    grant.init(access_granting_q)

    revoker = RevokeAccess()

    #Start the threads
    monitor.start()
    grant.start()
    revoker.start()



if __name__ == '__main__':

    if not os.geteuid() == 0:
        print ("Must run as root.")
        sys.exit(3)

    #parser = argparse.ArgumentParser()
    #args = parser.parse_args()

    hyp3rarmor_main()


import logging
import time
import threading
import socket
import netifaces as ni
import pcapy
from impacket.ImpactDecoder import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes,hmac 
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from hyp3rarmor.common.generate import valid_port, valid_ip, load_seed 
from hyp3rarmor.common.config import config 
from hyp3rarmor.common.constants import TOTP_LENGTH
from hyp3rarmor.common.exceptions import Hyp3rArmorCaptureError 

"""
This class is in charge of listening to the iptables log, verify if legit and 
if so add it to local cache.
"""

logger = logging.getLogger('monitor')

class NetMonitor(threading.Thread):

    def init(self, accept_q):
        self.accept_q = accept_q
        self.state = {}

    def _init_state_entry(self, src):
        """When a new IP address is received create a new entry. 
        @Args:
            src: the IP address of the client
        """
        logger.debug("Initializing new state for IP {}".format(src))
        self.state[src] = {}
        #Track the count of recieved destination ports
        self.state[src]["working"] =  {}
        #The window of possible tokens to match against
        self.state[src]["window"] = None
        #The minimum number of ports to receive for the client to authenticate
        self.state[src]["valid_port_count"] = 0
        #The time when this entry expires and the user has to restart
        self.state[src]["expire"] = time.time() + config.token_ttl

    def run(self):
        #Loop forever
        try:
            self.capture()
        except Exception as e:
            raise Hyp3rArmorCaptureError(e)


    def capture(self, timeout = 100):
        myip = ni.ifaddresses(config.iface)[2][0]['addr']
        logger.debug("My IP address is {}".format(myip))
        promisc = 1 
        cap_size = 65535 #max size tcp in bytes

        cap = pcapy.open_live(config.iface , cap_size , promisc , timeout)

        #Capture only TCP-SYN incoming packets
        cap.setfilter('tcp[13]=2 and not src net {}'.format(myip))
        #if we timeout we need to keep going
        while True:
            data = None
            try:
                (header, data) = cap.next()
            except pcapy.PcapError:
                continue
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(e)
            else:
                try:
                    if data:
                        packet = EthDecoder().decode(data)
                        (src_ip, dport) = self.parse_packet(packet)
                        if self.verify(src_ip, dport):
                            logger.debug("\tValid port received {}".format(src_ip))
                except Exception as e:
                    logger.error(e)

    def parse_packet(self, packet):
        """ Parse a packet to obtain the IP address and destination port

        Args:
            packet: a packet captured from libpcap

        Returns:
            Tuple (source IP address, destination port)

        Raises
            Hyp3rArmorCaptureError The parsed IP address and destination port are
            invalid
        """
        ip = packet.child()
        src_ip = ip.get_ip_src()
        tcp = ip.child()
        dport = tcp.get_th_dport()

        if not(valid_port(dport)): 
            raise Hyp3rArmorCaptureError("Parsed an invalid destination port {}".format(dport))

        if not(valid_ip(src_ip)):
            raise Hyp3rArmorCaptureError("Parsed an invalid IP address {}".format(src_ip))


        logger.debug("Received {}:{}".format(src_ip, dport))
        return (src_ip, dport)


    def verify(self, src_ip , dport): 
        """Verify if the "knock" is valid

        Args:
            src_ip: source IP address of the packet
            dport: destination port of the packet

        Returns:
            True if valid
        """
        #This is a critical section and must be as fast as possible

        client = self.state[src_ip]
        matched = []
        for token in client["window"]:
            # The received destination port is in our AT history
            if dport in token:
                # If we dont already have it then its still ok
                # or if we do have it and we havnt exceeded the number allowed
                if (dport not in client["working"]) or (client["working"][dport] + 1 <= token[dport]):
                    matched.append(token)


        if len(matched) > 0:
            # Of the returned matched, we know our working set is a subset
            client["window"] = matched
            del matched

            if dport not in client["working"]:
                client["working"][dport] = 1
            else: 
                client["working"][dport] += 1

            client["valid_port_count"] += 1
            print "c ", client["valid_port_count"]
            print "config ", config.minimum_receive
            if client["valid_port_count"] >= config.minimum_receive:
                self.state.pop(src_ip, 0)
                self.accept_q.put(src_ip)
                print "Added to queue"
            return True
        else:
            #Destination port does not match 
            self.state.pop(src_ip, 0)
            return False


class UniversalTokenNetMonitor(NetMonitor):

    def init(self, accept_q, token_state):
        self.token_state = token_state
        super(UniversalTokenNetMonitor, self).init(accept_q)

    def verify(self, src_ip, dport):
        """ Verify the received destination port is valid

        Args:
            src_ip: Source IP address
            dport: Destination port
        """
        #Init the clients state if they havnt been before or they 
        # have expired their time
        if ((src_ip not in self.state) or 
            (src_ip in self.state and self.state[src_ip]["expire"] < 
             time.time())):
            self._init_state_entry(src_ip)
            self.state[src_ip]["window"] =  self.token_state.window 

        return super(UniversalTokenNetMonitor, self).verify(src_ip, dport)
        

class IPBoundTokenNetMonitor(NetMonitor):
    def init(self, accept_q):
        
	file_path = os.path.join(HYP3RARMOR_ROOT, "seed.txt")
        self.totp = TOTP(load_seed(file_path), TOTP_LENGTH, 
                         hashes.SHA256(), config.token_ttl, backend=default_backend())
        super(IPBoundTokenNetMonitor, self).init(accept_q)

    def _construct_window(self, src_ip):
        """Construct the window of tokens 

        Args:
            src_ip: the source IP address to construct the window for

        Returns:
            An array of the tokens in the window 
        """

        window = []
        current_time = time.time()
        for i in xrange(config.window_size):
            t = current_time - (i * config.token_ttl)
            (old_token, old_time) = generate_ip_bound_token(config.token_size, src_ip, self.totp, t)
            window.append(old_token)

        return window

    def verify(self, src_ip, dport):
        if src_ip not in self.state:
            self._init_state_entry(src_ip)
            self.state[src_ip]["window"] = self._construct_window(src_ip)
        return super(IPBoundTokenNetMonitor, self).verify(src_ip, dport)




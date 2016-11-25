from time import sleep
import logging
import iptc
import time
import threading
from hyp3rarmor.common.config import config 
from hyp3rarmor.common.generate import time_till_dealth, valid_port, valid_ip
from hyp3rarmor.common.exceptions import  Hyp3rArmorFirewallError
from hyp3rarmor.common.constants import *
"""
This class revokes an IP addresses access
"""
#FIXME Look at a better way to do this asynchronized so we dont have 
#to loop through rules, this is probably slow


logger = logging.getLogger('firewall')

class Firewall(threading.Thread):

    COMMENT_TAG = "expire="


            
    def create_rule(self, ip, port):
        """Create a new firewall rule

        Args: 
            ip: IP address
            port: port number

        Returns:
            The firewall rule to white list

        Raises:
            Hyp3rArmorFirewallError: if something is wrong with the IP or port
        """

        if not(ip and valid_ip(ip)):
            raise Hyp3rArmorFirewallError("Not valid IP address: {}".format(ip))

        if not(port and valid_port(port)):
            raise Hyp3rArmorFirewallError("Not valid port: {}".format(port))

        rule = iptc.Rule()
        rule.src = str(ip) + "/32"
        rule.protocol = "tcp"
        rule.target = iptc.Target(rule, "ACCEPT")

        m_dport = iptc.Match(rule, "tcp")
        #iptc wants this as a string
        m_dport.dport = str(port)
        rule.add_match(m_dport)

        m_state = iptc.Match(rule, "state")
        m_state.state = "NEW"
        return rule


class RevokeAccess(Firewall):

    def revoke_from_cache(self):
        #TODO Not currently in use
        ips_to_delete = []
        for ip, state in self.cache.iteritems():
            if state["expire"] < time.time():
                ips_to_delete.append(ip)

        self.delete_by_ip(ips_to_delete)


    def delete_by_ip(self, ips):
        #TODO Not currently in use
        table = iptc.Table(iptc.Table.FILTER)
        #Refresh the table to see the new entries
        table.refresh()
        table.autocommit = False
        chain = iptc.Chain(table, "INPUT")
        changes_made = False
        for ip in ips:
            rule = self.create_rule(ip, config.access_ports)
            chain.delete_rule(rule)
            self.cache.pop(ip, 0)
            changes_made = True

        if changes_made:
            table.commit()
        table.autocommit = True

    def revoke(self):
        table = iptc.Table(iptc.Table.FILTER)
        #Refresh the table to see the new entries
        table.refresh()
        table.autocommit = False
        chain = iptc.Chain(table, "INPUT")
        changes_made = False
        for rule in chain.rules:
            if rule.protocol == "tcp":
                dport = None
                comment = None
                for match in rule.matches:
                    if match.name == "comment":
                        comment = match.comment
                    elif match.name == "tcp":
                        if match.dport:
                            dport = int(match.dport)
                if  dport == config.access_ports and self.COMMENT_TAG in comment:
                    seconds_till_expire_as_string = comment.split(self.COMMENT_TAG)[1]
                    try:
                        e = float(seconds_till_expire_as_string)
                        if e < time.time():
                            chain.delete_rule(rule)
                            changes_made = True
                            logger.debug("Revoking access for {}".format(rule.src))
                    except Exception as e:
                        logger.error(e)
        if changes_made:
            table.commit()
        table.autocommit = True

    def run(self):
        try:
            while True:
                self.revoke()
                sleep(config.token_ttl)                
        except Exception as e:
            logger.error(e)



class GrantAccess(Firewall):

    def init(self, access_q):

        self.access_q = access_q


    def _whitelist_ip(self, ip):
        """
        White list an IP addresses immediately and set it to expire at the next 
        full token TTL time

        Args:
            ip: The IP address to white list

        Raises:
            Hyp3rArmorFirewallError: Invalid IP address 
        """
        if not(ip and valid_ip(ip)):
            raise Hyp3rArmorFirewallError("Not valid IP address: {}".format(ip))

        rule = self.create_rule(ip, config.access_ports)

        time_left = time_till_dealth(config.token_ttl)
        expire_time= time.time() + time_left + config.token_ttl 
        m_comment = iptc.Match(rule, "comment")
        m_comment.comment = "{}{}".format(self.COMMENT_TAG, expire_time)
        rule.add_match(m_comment)

        table = iptc.Table(iptc.Table.FILTER)
        table.refresh()
        chain = iptc.Chain(table, "INPUT")
        chain.insert_rule(rule)

        logger.debug("Whitelisted {}".format(ip))

    def is_ip_whitelisted(self, ip):
        """Check if an IP is already white listed

        Args:
            ip: IP address to check

        Returns:
            True if already white listed

        Raises:
            Hyp3rArmorFirewallError: Invalid IP address 
        """
        if not(ip and valid_ip(ip)):
            raise Hyp3rArmorFirewallError("Not valid IP address: {}".format(ip))

        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, "INPUT")
        rule = self.create_rule(ip, config.access_ports)
        return rule in chain.rules

    def run(self):
        """Loop forever reading IP addresses to be white listed"""
        try:
            while True:
                ip = self.access_q.get()
                print "Got ip ", ip
                if not self.is_ip_whitelisted(ip):
                    self._whitelist_ip(ip)
        except Exception as e:
            logger.error(e)




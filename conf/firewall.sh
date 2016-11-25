#!/bin/sh

#Help from https://gist.github.com/thomasfr/9712418

IPTABLES="/sbin/iptables"
# IP address of adminstrating machine
JUMP=

#Flush all previous rules
$IPTABLES -F


#Whitelist the jump server for ssh
$IPTABLES -A INPUT -m state --state NEW,RELATED,ESTABLISHED -p tcp -s $JUMP/32 --dport 22 -j ACCEPT
$IPTABLES -A INPUT -m state --state RELATED,ESTABLISHED -p tcp --dport 22 -j ACCEPT

#Allow internal connections, required for ntpq
$IPTABLES -A INPUT -p all -j ACCEPT -s 127.0.0.1 -d 127.0.0.1


# We want to allow open connections
#$IPTABLES -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Allow everything out
$IPTABLES -A OUTPUT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
#$IPTABLES -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

#Allow HTTPS out for git
$IPTABLES -A OUTPUT -p tcp -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES  -A INPUT -p tcp -m multiport --sports 80,443 -m state --state ESTABLISHED -j ACCEPT

#Allow ssh out
$IPTABLES -A OUTPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES  -A INPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

#DNS
$IPTABLES -A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT

#PINGS
$IPTABLES -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A INPUT -p icmp -m state --state ESTABLISHED,RELATED -j ACCEPT


#NTP
$IPTABLES -A OUTPUT -p udp --dport 123 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -p udp --sport 123 -m state --state ESTABLISHED -j ACCEPT

$IPTABLES -A OUTPUT -j ACCEPT

# We want to reject any attempts to forward
$IPTABLES -A FORWARD -j REJECT

#TODO
$IPTABLES -A INPUT -j REJECT


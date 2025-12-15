#!/bin/bash
DEV_MTU=1500

DEV_SERVER="vpn_server"
DEV_CLIENT="vpn_client"
NETNS_DIALIN="vpn_client"

VPN_POOL="11.0.0.1/24"
#VPN_POOL="affe::1/64"

LOCAL_IPV4="198.18.200.1/24"
REMOTE_IPV4="198.18.200.2/24"

LOCAL_IPV6="fdff::1/64"
REMOTE_IPV6="fdff::2/64"

#ARGS="--debug"
ARGS="--benchmark"
MAX_CLIENTS=3

CONFIG="basicauth"
#CONFIG="mutual"

#HOSTNAME=${LOCAL_IPV4%/*}
HOSTNAME=${LOCAL_IPV6%/*}

if [ "$USER" != "root" ]; then
	echo "Switching to root"
	sudo $0 $@
	exit
fi
cd test

if [[ "$VPN_POOL" == *:* ]]; then
	echo "Found IPv6 pool"
	IPREQUEST="::"
else
	echo "Found IPv4 pool"
	IPREQUEST="0.0.0.0"
fi
PING_IP=${VPN_POOL%/*}

create_transfer()
{
	create_netns $NETNS_DIALIN

	ip link add $DEV_SERVER type veth peer name $DEV_CLIENT
	ip link set dev $DEV_SERVER mtu $DEV_MTU
	ip link set dev $DEV_CLIENT mtu $DEV_MTU
	ip link set $DEV_CLIENT netns $NETNS_DIALIN

	ip link set $DEV_SERVER up
	ip addr add $LOCAL_IPV4 dev $DEV_SERVER
	ip addr add $LOCAL_IPV6 dev $DEV_SERVER

	ip netns exec $NETNS_DIALIN ip link set $DEV_CLIENT up
	ip netns exec $NETNS_DIALIN ip addr add $REMOTE_IPV4 dev $DEV_CLIENT
	ip netns exec $NETNS_DIALIN ip addr add $REMOTE_IPV6 dev $DEV_CLIENT
}

create_netns()
{
	NETNS=$1

	[ -e /var/run/netns ] || mkdir -p /var/run/netns
	[ -e /var/run/netns/default ] || ln -s /proc/1/ns/net /var/run/netns/default
	[ -e /var/run/netns/$NETNS ] && return

	echo "Creating netns $NETNS"
	ip netns add $NETNS
	ip netns exec $NETNS ip link set lo up
}

start_server()
{
	../bin/h3tunnel --config_file config_server_${CONFIG}.cfg  --pool $VPN_POOL --log_prefix server $ARGS &
	echo "Started server process with pid $!"
}

start_client()
{
	NAME=$1
	create_netns $NAME
	ip netns exec $NETNS_DIALIN ../bin/h3tunnel_client --config_file config_client_${CONFIG}.cfg --hostname $HOSTNAME --netns $NAME --log_prefix $NAME --iprequest $IPREQUEST $ARGS &
	echo "Started client $NAME process with pid $!"

	sleep 3
	ip netns exec $NAME ping -c 3 $PING_IP
}

create_transfer

start_server
SERVER_PID=$!

sleep 2

let CHILD=0
CHILD_PIDS=()
while [ "$CHILD" -lt $MAX_CLIENTS ]
do
	start_client "client$CHILD"
	CHILD_PIDS+=($!)
	let CHILD++
done

sleep 15
echo "done, terminating..."

for CHILD_PID in ${CHILD_PIDS[@]}
do
	echo "Killing $CHILD_PID"
	kill $CHILD_PID
	sleep 1
done
kill $SERVER_PID
sleep 1

ip link del $DEV_SERVER

exit

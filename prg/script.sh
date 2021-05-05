#!/bin/bash

echo 1 > /proc/sys/net/ipv4/ip_forward

function new_vrf {
local num=$1

ip link add dev mvrf$num type vrf table $num
ip link set dev mvrf$num up


local h_ip=1.1.$num.1
local m_ip=1.1.$num.$num

ip netns add mns$num

ip link add mrp$num type veth peer minion$num # vrf mvrf$num

ip li set minion$num netns mns$num

ip -n mns$num addr add dev minion$num $m_ip/24
ip addr add dev mrp$num $h_ip/24
ip -n mns$num link set dev minion$num up
ip link set dev mrp$num up


ip -n mns$num link set lo up

# exec in ns if needed
echo 1 | sudo tee /proc/sys/net/ipv4/conf/minion$num/proxy_arp
echo 1 | sudo tee /proc/sys/net/ipv4/conf/minion$num/accept_local
echo 1 | sudo tee /proc/sys/net/ipv4/conf/minion$num/forwarding
echo 0 | sudo tee /proc/sys/net/ipv4/conf/minion$num/rp_filter

echo 1 | sudo tee /proc/sys/net/ipv4/conf/mrp$num/proxy_arp
echo 1 | sudo tee /proc/sys/net/ipv4/conf/mrp$num/accept_local
echo 1 | sudo tee /proc/sys/net/ipv4/conf/mrp$num/forwarding
echo 0 | sudo tee /proc/sys/net/ipv4/conf/mrp$num/rp_filter

sudo ip netns exec mns$num ip route add default via $m_ip

}

new_vrf 2
new_vrf 3
new_vrf 4

# ip nei ch 1.1.13.1 lladdr 3e:38:1d:6c:32:2a dev minion13 nud permanent

#sudo ip netns exec mns2 socat STDIO UDP-LISTEN:11111
#sudo ip netns exec mns3 echo "La "| socat - UDP-DATAGRAM:1.1.2.2:11111,sp=11111
#sudo ip netns exec mns4 echo "La "| socat - UDP-DATAGRAM:1.1.2.2:11111,sp=11111




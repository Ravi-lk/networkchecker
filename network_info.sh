#!/bin/bash

# Check network interfaces and IP addresses
echo "Network Interfaces and IP addresses:"
ip addr show

# Check routing table
echo "Routing Table:"
ip route show

# Check DNS settings
echo "DNS Settings:"
cat /etc/resolv.conf

# Check open ports
echo "Open Ports:"
netstat -tuln

# Check firewall rules (iptables example)
echo "Firewall Rules:"
sudo iptables -L -v -n

#!/bin/bash

# Check for Ethernet connection
if ip link show eth0 | grep "state UP" > /dev/null; then
    echo "Ethernet is connected. Ensuring network services are active."
    sudo systemctl enable zerotier-one
    sudo systemctl start zerotier-one
    sudo systemctl disable hostapd
    sudo systemctl disable dnsmasq
    sudo systemctl stop hostapd
    sudo systemctl stop dnsmasq
else
    echo "Ethernet is not connected. Enabling Access Point mode."
    sudo systemctl enable hostapd
    sudo systemctl enable dnsmasq
    sudo systemctl start hostapd
    sudo systemctl start dnsmasq
    sudo systemctl disable zerotier-one
    sudo systemctl stop zerotier-one
fi

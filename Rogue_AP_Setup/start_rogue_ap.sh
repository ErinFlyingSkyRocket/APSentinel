#!/bin/bash
# ===============================================
# Rogue AP Auto Setup Script (hostapd + dnsmasq)
# ===============================================

# CONFIGURE INTERFACES
WLAN="wlan0"
INTERNET_IF="eth0"
AP_IP="10.0.0.1"
AP_NETMASK="255.255.255.0"

# CONFIG FILE LOCATIONS (edit if needed)
HOSTAPD_CONF="/root/awus/rtl8812au/hostapd.conf"
DNSMASQ_CONF="/root/awus/rtl8812au/dnsmasq.conf"

echo "[*] Stopping conflicting services..."
sudo systemctl stop NetworkManager.service wpa_supplicant.service 2>/dev/null

echo "[*] Resetting interface $WLAN..."
sudo ip link set $WLAN down
sudo ip addr flush dev $WLAN
sudo ip addr add $AP_IP/24 dev $WLAN
sudo ip link set $WLAN up

echo "[*] Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1

echo "[*] Flushing and setting up iptables for NAT..."
sudo iptables -t nat -F
sudo iptables -F FORWARD
sudo iptables -t nat -A POSTROUTING -o $INTERNET_IF -j MASQUERADE
sudo iptables -A FORWARD -i $INTERNET_IF -o $WLAN -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i $WLAN -o $INTERNET_IF -j ACCEPT

echo "[*] Starting hostapd..."
sudo pkill hostapd 2>/dev/null
sudo hostapd $HOSTAPD_CONF -B

echo "[*] Starting dnsmasq..."
sudo pkill dnsmasq 2>/dev/null
sudo dnsmasq -C $DNSMASQ_CONF -d &

echo "[*] Checking interface and routing..."
ip addr show $WLAN | grep "inet "
sudo iptables -t nat -L -n -v | grep MASQUERADE

echo "[+] Rogue Access Point started successfully!"
echo "[+] SSID should now be visible. Clients will get IPs from dnsmasq and internet via $INTERNET_IF."

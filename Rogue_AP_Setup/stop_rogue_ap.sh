#!/bin/bash
sudo pkill hostapd
sudo pkill dnsmasq
sudo iptables -t nat -F
sudo iptables -F FORWARD
sudo systemctl start NetworkManager.service
sudo systemctl start wpa_supplicant.service
echo "[+] Rogue AP stopped and system network restored."

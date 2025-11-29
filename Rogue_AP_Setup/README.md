# Rogue AP Setup with RTL8812AU (AWUS036ACH)

## 📌 Kali Linux Version Required

-   **Kali-Linux-2018.2-vm-amd64**\
    Download: `https://old.kali.org/kali-images/kali-2018.2/`

------------------------------------------------------------------------

## 📦 Packages Required

Download these `.deb` packages:

    linux-headers-4.15.0-kali2-common_4.15.11-1kali1_all.deb
    linux-headers-4.15.0-kali2-amd64_4.15.11-1kali1_amd64.deb
    linux-kbuild-4.15_4.15.11-1kali1_amd64.deb
    linux-compiler-gcc-7-x86_4.15.11-1kali1_amd64.deb
    dnsmasq_2.80-1.1_all.deb
    hostapd_2.6-21_amd64.deb

Sources:

    http://old.kali.org/kali/pool/main/l/linux/
    https://old.kali.org/kali/pool/main/d/
    https://old.kali.org/kali/pool/main/w/wpa/

Install them:

    sudo dpkg -i *.deb
    sudo apt-get -f install

------------------------------------------------------------------------

## 🔌 USB WiFi Adapter

**Alfa AWUS036ACH (RTL8812AU chipset)**

------------------------------------------------------------------------

## ⚙️ Driver Setup (RTL8812AU)

### **Step 1 --- Clone driver**

    git clone https://github.com/aircrack-ng/rtl8812au.git
    cd rtl8812au

### **Step 2 --- Build and install**

    make clean
    make
    sudo make install

### **Step 3 --- Load the module**

    sudo modprobe 8812au

### **Step 4 --- Verify**

    iwconfig
    lsusb

You should see `wlan0` or `wlan1` listed and Realtek USB detected.

------------------------------------------------------------------------

## 🚨 Rogue AP Setup

### **To start Rogue AP**

    ./start_rogue_ap.sh

### **To stop Rogue AP**

    ./stop_rogue_ap.sh

Ensure correct config paths in both scripts:

    HOSTAPD_CONF="/root/awus/rtl8812au/hostapd.conf"
    DNSMASQ_CONF="/root/awus/rtl8812au/dnsmasq.conf"

`hostapd.conf` and `dnsmasq.conf` must both be present in the directory.

------------------------------------------------------------------------

## 🛠 Troubleshooting

-   Ensure `sudo modprobe 8812au` has **no errors**
-   Ensure VMware/VirtualBox **USB 3.0/3.1** is enabled\
-   Ensure the system sees the adapter via `lsusb`
-   If you find that there are errors when running the `hostapd.conf` and `dnsmasq.conf`, it should be resolved when you remove the comments in the file
-   It is best to run the following commands before testing the Rogue AP `sudo systemctl restart NetworkManager` and `sudo dhclient -v eth0`


------------------------------------------------------------------------

## ✅ This setup includes:

-   Hostapd (patched 2.6)
-   Dnsmasq for DHCP
-   Proper RTL8812AU drivers
-   Scripts for clean start/stop workflow
-   Tested on Kali Linux **2018.2**

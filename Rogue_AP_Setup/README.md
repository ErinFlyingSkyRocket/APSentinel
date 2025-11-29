Kali Linux Version Required: 
```
Kali-Linux-2018.2-vm-amd64
```

Link:
```
https://old.kali.org/kali-images/kali-2018.2/
```

Packages Required:
```
linux-headers-4.15.0-kali2-common_4.15.11-1kali1_all.deb
linux-headers-4.15.0-kali2-amd64_4.15.11-1kali1_amd64.deb
linux-kbuild-4.15_4.15.11-1kali1_amd64.deb
linux-compiler-gcc-7-x86_4.15.11-1kali1_amd64.deb
dnsmasq_2.80-1.1_all.deb
hostapd_2.6-21_amd64.deb
```

Link:
```
http://old.kali.org/kali/pool/main/l/linux/
http://old.kali.org/kali/pool
```

Installation of Packages:
```
sudo dpkg -i *.deb
sudo apt-get -f install
```

Setting up Environment:

Step 1: Clone the Driver Repository
Download the official driver repository for RTL8812AU:

```
   git clone https://github.com/aircrack-ng/rtl8812au.git
   cd rtl8812au
```
                 
Step 2: Build and Install the Driver
Now compile and install the driver:

```
   make clean
   make
   sudo make install
```
                     
Step 3: Load the Module
After installation, load the kernel module:

```
   sudo modprobe 8812au
```
                     
Step 4: Verify the Installation
Check if the adapter and usb is detected:

```
   iwconfig
   lsusb
```                     
You should see an interface like wlan1 or wlan0 or realtek usb detected depending on your system.

Trouble Shooting:
If the adapter and usb is not detected, please verify that ```sudo modprobe 8812au``` does not throw any errors

Check if your vmware/virtual box enables usb3.0/3.1 connections

To start testing RogueAP:
Run the Script ```start_rogue_ap.sh```

Run the Script ```stop_rogue_ap.sh``` to stop the processes

The config files for ```hostapd.conf``` and ```dnsmaq.conf``` are provided

Ensure that the config files location are properly reflected in the ```start_rogue_ap.sh``` and ```stop_rogue_ap.sh``` script

```
HOSTAPD_CONF="/root/awus/rtl8812au/hostapd.conf"
DNSMASQ_CONF="/root/awus/rtl8812au/dnsmasq.conf"
```

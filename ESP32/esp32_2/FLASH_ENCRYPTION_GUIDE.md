# ⚠️⚠️ WARNING — FLASH ENCRYPTION & EFUSE BURNING IS PERMANENT ⚠️⚠️

Enabling **ESP32 Flash Encryption**, **burning the flash encryption key**, and **setting FLASH_CRYPT_CNT eFuses** are **one-way, irreversible operations**.

Once you proceed:

* ❌ You **cannot disable** flash encryption
* ❌ You **cannot revert** the microcontroller to normal Arduino upload mode
* ❌ You **cannot boot unencrypted firmware ever again**
* ❌ You **cannot erase or reset eFuses**
* ❌ You **cannot recover the device if the encryption key is lost**
* ❌ Flashing unencrypted bootloader/partitions afterward may **permanently brick** the device

This provides strong security:

* ✔ Prevents firmware cloning
* ✔ Prevents dumping or reverse engineering firmware
* ✔ Ensures only encrypted firmware with your key can boot
* ✔ Ideal for APSentinel evidence-integrity and anti-tampering

👉 Proceed **ONLY if you understand and accept the consequences**.
👉 **BACK UP your encryption key securely**:

```
my_flash_encryption_key.bin
```

If this key is lost, the ESP32 **can never be reflashed again**.

---

# **FLASH_ENCRYPTION_Guide.md**

### **ESP32 Flash Encryption Workflow for APSentinel (Windows, Arduino + ESP-IDF 5.5)**

This guide provides the complete secure flashing workflow for ESP32 WROOM/WROOM-DA devices.

---

# **0. Requirements**

Install:

* **ESP-IDF v5.5** (Windows installer)
* **Python 3.11**
* **Arduino IDE** (for coding only)
* USB serial driver (CP210x/CH340)

---

# **1. Export the Arduino Sketch**

In Arduino IDE:

```
Sketch → Export Compiled Binary
```

Generated files:

```
esp32_2.ino.bin
esp32_2.ino.bootloader.bin
esp32_2.ino.partitions.bin
```

Move them to:

```
APSentinel/ESP32/esp32_2/build/esp32.esp32.esp32da/
```

---

# **2. Activate ESP-IDF Environment**

Open:

```
ESP-IDF 5.5 PowerShell
```

Expected output:

```
Activating ESP-IDF 5.5...
Done! You can now compile ESP-IDF projects.
```

---

# **3. Generate Flash Encryption Key**

```bash
cd C:\Users\<YOU>\Desktop\Apsentinel\ESP32\esp32_2\build\esp32.esp32.esp32da
espsecure.py generate_flash_encryption_key my_flash_encryption_key.bin
```

⚠ **Do not commit this file**
⚠ Store backups securely

---

# **4. Encrypt All Firmware Components**

### Bootloader

```bash
espsecure.py encrypt_flash_data --keyfile my_flash_encryption_key.bin ^
  --address 0x1000 esp32_2.ino.bootloader.bin bootloader-enc.bin
```

### Partition Table

```bash
espsecure.py encrypt_flash_data --keyfile my_flash_encryption_key.bin ^
  --address 0x8000 esp32_2.ino.partitions.bin partitions-enc.bin
```

### Application Binary

```bash
espsecure.py encrypt_flash_data --keyfile my_flash_encryption_key.bin ^
  --address 0x10000 esp32_2.ino.bin app-enc.bin
```

You now have:

* `bootloader-enc.bin`
* `partitions-enc.bin`
* `app-enc.bin`

---

# **5. Burn Flash Encryption eFuses (ONE TIME ONLY)**

⚠ Irreversible. Cannot “unburn” or revert.

### Burn flash encryption key:

```bash
espefuse.py --port COM4 burn_key flash_encryption my_flash_encryption_key.bin
```

### Set FLASH_CRYPT_CNT to odd number:

```bash
espefuse.py --port COM4 burn_bit FLASH_CRYPT_CNT 0
```

Run this **7 times** until the count is odd.

### Verify:

```bash
espefuse.py --port COM4 summary
```

Look for:

```
FLASH_CRYPT_CNT = (odd)   <-- encryption enabled
```

---

# **6. Flash the Encrypted Firmware**

```bash
esptool.py --chip esp32 --port COM4 --baud 460800 write_flash ^
  0x1000 bootloader-enc.bin ^
  0x8000 partitions-enc.bin ^
  0x10000 app-enc.bin
```

Then unplug + replug the ESP32.

---

# **7. Verify Flash Encryption**

Check eFuses:

```bash
espefuse.py --port COM4 summary
```

Test-read flash (should be scrambled noise):

```bash
esptool.py --chip esp32 --port COM4 read_flash 0x10000 0x20000 dump.bin
```

Open `dump.bin` — if encrypted, it will be unreadable.

---

# **8. Serial Monitor**

Works normally — flash encryption does **not** affect UART.

Arduino IDE:

* Tools → Port → COM4
* Tools → Serial Monitor
* Baud: `115200`

---

# **9. Update Firmware (Normal Workflow)**

### Step 1 — Export new binary

```
Sketch → Export Compiled Binary
```

Place in build folder.

### Step 2 — Re-encrypt the app image

```bash
espsecure.py encrypt_flash_data --keyfile my_flash_encryption_key.bin ^
  --address 0x10000 esp32_2.ino.bin app-enc.bin
```

### Step 3 — Flash encrypted app only

```bash
esptool.py --chip esp32 --port COM4 --baud 460800 write_flash ^
  0x10000 app-enc.bin
```

No need to reflash bootloader or partitions unless changed.

---

# **10. Full Device Erase**

```bash
esptool.py --port COM4 erase_flash --force
```

Even after erasing flash:

* Flash encryption **remains enabled**
* Device **cannot** accept unencrypted firmware
* You must always flash encrypted images

---

# **11. Important Security Notes**

* Flash encryption **cannot be reversed**
* Bootloader, partition table, and app **must all be encrypted**
* The encryption key must be protected
* Without the key, the device cannot be reflashed
* Prevents cloning + reverse engineering
* Secures APSentinel’s evidence-chain firmware

---

# **12. Optional Automated Flash Script**

Create:

```
encrypt_and_flash_app.bat
```

Contents:

```bat
@echo off
call "C:\Espressif\frameworks\esp-idf-v5.5.1\export.bat"
cd "%~dp0"

espsecure.py encrypt_flash_data --keyfile my_flash_encryption_key.bin ^
    --address 0x10000 esp32_2.ino.bin app-enc.bin

esptool.py --chip esp32 --port COM4 --baud 460800 write_flash ^
    0x10000 app-enc.bin

pause
```

Use this script every time you update firmware.

---

# ✔ Your ESP32 Is Now Fully Secured

* Firmware encrypted
* Device unclonable
* Bootloader protected
* Evidence chain integrity preserved
* Anti-tampering strong enough for forensic environments

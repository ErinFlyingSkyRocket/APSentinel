@echo off
setlocal

REM === 0. Load ESP-IDF environment ===
call "C:\Espressif\frameworks\esp-idf-v5.5.1\export.bat"
if errorlevel 1 (
  echo [!] ERROR: Failed to load ESP-IDF environment.
  pause
  exit /b 1
)

REM === CONFIG ===
set PORT=COM4
set DIR=C:\Users\Erinc\Desktop\Apsentinel\ESP32\esp32_2\build\esp32.esp32.esp32da
set KEYFILE=my_flash_encryption_key.bin
set BOOT_PLAIN=esp32_2.ino.bootloader.bin
set PART_PLAIN=esp32_2.ino.partitions.bin
set APP_PLAIN=esp32_2.ino.bin
set BOOT_ADDR=0x1000
set PART_ADDR=0x8000
set APP_ADDR=0x10000
set BOOT_ENC=bootloader-enc.bin
set PART_ENC=partitions-enc.bin
set APP_ENC=app-enc.bin
REM =============

echo [*] Changing to build directory...
cd /d "%DIR%" || (
  echo [!] ERROR: Cannot cd into "%DIR%"
  pause
  exit /b 1
)

if not exist "%KEYFILE%" (
  echo [!] ERROR: Key file "%KEYFILE%" not found.
  pause
  exit /b 1
)

if not exist "%BOOT_PLAIN%" (
  echo [!] ERROR: Bootloader binary "%BOOT_PLAIN%" not found.
  pause
  exit /b 1
)

if not exist "%PART_PLAIN%" (
  echo [!] ERROR: Partition table binary "%PART_PLAIN%" not found.
  pause
  exit /b 1
)

if not exist "%APP_PLAIN%" (
  echo [!] ERROR: App binary "%APP_PLAIN%" not found.
  echo     In Arduino: Sketch -> Export Compiled Binary, then run this script again.
  pause
  exit /b 1
)

echo [*] Encrypting bootloader...
python -m espsecure encrypt_flash_data ^
  --keyfile "%KEYFILE%" ^
  --address %BOOT_ADDR% ^
  --output "%BOOT_ENC%" ^
  "%BOOT_PLAIN%"

if errorlevel 1 (
  echo [!] ERROR: espsecure (bootloader) failed.
  pause
  exit /b 1
)

echo [*] Encrypting partition table...
python -m espsecure encrypt_flash_data ^
  --keyfile "%KEYFILE%" ^
  --address %PART_ADDR% ^
  --output "%PART_ENC%" ^
  "%PART_PLAIN%"

if errorlevel 1 (
  echo [!] ERROR: espsecure (partitions) failed.
  pause
  exit /b 1
)

echo [*] Encrypting app image...
python -m espsecure encrypt_flash_data ^
  --keyfile "%KEYFILE%" ^
  --address %APP_ADDR% ^
  --output "%APP_ENC%" ^
  "%APP_PLAIN%"

if errorlevel 1 (
  echo [!] ERROR: espsecure (app) failed.
  pause
  exit /b 1
)

echo [*] Flashing all encrypted images to %PORT% ...
esptool.py --chip esp32 --port %PORT% --baud 460800 ^
  --before default_reset --after hard_reset ^
  write_flash -z ^
  %BOOT_ADDR% "%BOOT_ENC%" ^
  %PART_ADDR% "%PART_ENC%" ^
  %APP_ADDR%  "%APP_ENC%"

if errorlevel 1 (
  echo [!] ERROR: esptool.py write_flash failed.
  pause
  exit /b 1
)

echo [✓] Done! Encrypted bootloader, partitions, and app flashed successfully.
pause
endlocal

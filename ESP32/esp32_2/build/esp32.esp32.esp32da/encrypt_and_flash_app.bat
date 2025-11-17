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
set APP_PLAIN=esp32_2.ino.bin
set APP_ADDR=0x10000
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
  echo     Make sure my_flash_encryption_key.bin is in this folder.
  pause
  exit /b 1
)

if not exist "%APP_PLAIN%" (
  echo [!] ERROR: App binary "%APP_PLAIN%" not found.
  echo     In Arduino: Sketch -> Export Compiled Binary, then run this script again.
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
  echo [!] ERROR: espsecure (encrypt app) failed.
  pause
  exit /b 1
)

echo [*] Flashing encrypted app to %PORT% at %APP_ADDR% ...
esptool.py --chip esp32 --port %PORT% --baud 460800 ^
  --before default_reset --after hard_reset ^
  write_flash %APP_ADDR% "%APP_ENC%"

if errorlevel 1 (
  echo [!] ERROR: esptool.py write_flash failed.
  pause
  exit /b 1
)

echo [✓] Done! Encrypted app flashed successfully.
pause
endlocal

# 🛰️ Apsentinel — Network Forensics Dashboard

Apsentinel is a **Django-based network forensics web application** for managing and visualizing Wi-Fi observations collected from registered ESP32 sensors.
It maintains an **append-only evidence chain**, verifying each observation’s integrity and ensuring authenticity using ECDSA and SHA-256.

---

## ⚙️ 1. Features

* 🧩 **Device registration** — manage ESP32 devices and their public keys
* 🛰️ **Observation logs** — view SSID/BSSID/RSSI data collected in real time
* 🔒 **Hash-chained evidence** — detect tampering with cryptographic verification
* 📊 **Dashboard** — total observations, active devices, and last event summary
* 🔐 **User login required** — secure web interface via Django authentication
* 🎨 **Unified dark theme** — all pages share one CSS file (`templates/css/style.css`)

---

## 🚀 2. Setup Instructions

### Step 1 — Create virtual environment and install dependencies

```bash
python -m venv .venv
.venv\Scripts\activate    # (on Windows)
# or source .venv/bin/activate (on macOS/Linux)

pip install -r requirements.txt
```

If `requirements.txt` doesn’t exist, create it manually:

```txt
Django>=5.0
cryptography
```

---

### Step 2 — Initialize database

```bash
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

---

### Step 3 — Run the development server

```bash
python manage.py runserver
```

Then open [http://127.0.0.1:8000](http://127.0.0.1:8000)

* **Login:** `/accounts/login/`
* **Dashboard:** `/`
* **Observations:** `/ui/observations`
* **Devices:** `/ui/devices`

---

## 🧩 3. Configuration Notes

* The project uses **SQLite** by default — ideal for quick testing and analysis.
* All web templates and static CSS are stored directly in `templates/`.
* Static configuration in `settings.py`:

  ```python
  STATIC_URL = '/static/'
  STATICFILES_DIRS = [BASE_DIR / "templates"]
  ```

---

## 🔐 4. Authentication and Access

Only authenticated users can access the dashboard, devices, and observation logs.

Run once to create an admin:

```bash
python manage.py createsuperuser
```

Then log in at:
👉 [http://127.0.0.1:8000/accounts/login/](http://127.0.0.1:8000/accounts/login/)

---

## 🧠 5. ESP32 Data Flow (Concept)

* Each ESP32 is registered in **Devices** (stores `name`, `pubkey_pem`, `is_active`).
* When the system receives Wi-Fi observation data or packets,
  Apsentinel verifies authenticity and appends them as **Observation** records.
* Each record maintains:

  * Payload hash (SHA-256)
  * Previous chain hash
  * Device signature

This ensures **tamper-evident logs** — ideal for forensic traceability.

---

## 🎨 6. Styling

All pages share a single stylesheet:

```
templates/css/style.css
```

Update once, and every page (Dashboard, Observations, Devices, Login) inherits the new design automatically.

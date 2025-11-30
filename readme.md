# 🛰️ Apsentinel — Network Forensics Dashboard
# 🛰️ Apsentinel — Network Forensics Dashboard
Apsentinel is a **Django-based network forensics web application** for managing and visualizing Wi-Fi observations collected from registered **ESP32 sensors**.  
It maintains an **append-only evidence chain**, verifying each observation’s integrity and ensuring authenticity using **ECDSA + SHA-256** cryptography.

---

## ⚙️ 1. Features

* 🧩 **Device registration** — manage ESP32 devices and their public keys  
* 🛰️ **Observation logs** — view SSID/BSSID/RSSI data collected in real time  
* 🔒 **Hash-chained evidence** — tamper detection via cryptographic verification  
* 📊 **Dashboard** — total observations, active devices, and last event summary  
* 🔐 **Authentication** — secure access via Django’s login system  
* 🎨 **Unified dark theme** — single CSS shared across all pages  

---

## 🧰 2. Local Development Setup

### Step 1 — Create virtual environment and install dependencies

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
````

If `requirements.txt` doesn’t exist:

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

### Step 3 — Run locally

```bash
python manage.py runserver
```

Then open **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

* Login: `/accounts/login/`
* Dashboard: `/`
* Observations: `/ui/observations`
* Devices: `/ui/devices`

---

## 🌐 3. Deploying to AWS (EC2 Ubuntu Example)

### Step 1 — Connect to EC2

```bash
ssh -i "your-key.pem" ubuntu@<your-ec2-ip>
sudo apt update && sudo apt install -y python3 python3-venv git
```

### Step 2 — Clone and enter project

```bash
git clone https://github.com/ErinFlyingSkyRocket/APSentinel.git
cd APSentinel
```

### Step 3 — Setup Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install django cryptography python-dotenv
```

### Step 4 — Database setup

```bash
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

### Step 5 — Run Django (open to all interfaces)

```bash
python manage.py runserver 0.0.0.0:8000
```

> **Note:**
> In AWS → EC2 → Security Groups, add an inbound rule for **TCP 8000** (source `0.0.0.0/0` or your own IP range).

Access from browser or ESP32:

```text
http://<your-ec2-ip>:8000
```

---

## 🔄 3.1 Updating to the Latest Version (Git Pull on EC2)

When you push new commits to GitHub, update your EC2 instance with:

### Step 1 — Go to project directory

```bash
cd ~/APSentinel
```

### Step 2 — See your current branch and status (optional but helpful)

```bash
git status
git branch
```

### Step 3 — Pull latest code from `origin/main` (safe, keeps local changes)

```bash
git fetch origin
git checkout main
git pull origin main
```

### Step 4 — Force reset to GitHub version (discard local changes)

If you want the EC2 copy to **exactly match GitHub**, ignoring all local edits:

```bash
git fetch origin
git checkout main
git reset --hard origin/main
```

> 💡 Use this when you accidentally broke something on EC2 and just want to “go back to whatever is on GitHub”.

### Step 5 — Apply migrations again (if models changed)

```bash
source .venv/bin/activate
python manage.py migrate
```

### Step 6 — Restart Django dev server

```bash
python manage.py runserver 0.0.0.0:8000
```

(If you later switch to `gunicorn`/`systemd`, this step would become `sudo systemctl restart apsentinel` or similar.)

---

## 🧪 4. Optional: Use Self-Signed HTTPS PEM (No Certbot Needed)

If you want to demo **encrypted uploads** without external certificates:

### Step 1 — Generate a self-signed certificate

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -subj "/CN=apsentinel.local"
```

### Step 2 — Install Django Extensions

```bash
pip install django-extensions
```

### Step 3 — Run with HTTPS

```bash
python manage.py runserver_plus --cert-file server.crt --key-file server.key 0.0.0.0:8443
```

### Step 4 — Update your ESP32 sketch

```cpp
#define SERVER_HOST "https://<your-ec2-ip>:8443"
#define SERVER_PATH "/api/ingest/esp32/"
static const char *ROOT_CA_PEM = R"PEM(
-----BEGIN CERTIFICATE-----
(paste contents of server.crt here)
-----END CERTIFICATE-----
)PEM";
```

Now your ESP32 → Django traffic is encrypted with your self-signed PEM.
No Certbot or nginx required.

---

## 🧠 5. ESP32 → Apsentinel Data Flow

1. ESP32 scans nearby Wi-Fi APs.

2. Builds canonical entries (SSID/BSSID/RSSI/etc.).

3. Each record is hashed (SHA-256) and signed (ECDSA P-256).

4. The device sends JSON to:

   ```text
   http://<ec2-ip>:8000/api/ingest/esp32/
   ```

   or, if using HTTPS PEM:

   ```text
   https://<ec2-ip>:8443/api/ingest/esp32/
   ```

5. Django verifies signature, device key, and chain integrity.

6. Valid data is appended as a tamper-evident observation.

---

## 📦 6. Project Structure

```text
APSentinel/
│
├── devices/                 # Device registration & management
├── evidence/                # Ingestion, whitelist, evidence chain
├── templates/               # HTML templates & CSS
├── manage.py
├── requirements.txt
└── README.md
```

---

## 🎨 7. Styling

All pages share one stylesheet:

```text
templates/css/style.css
```

Update it once and all pages inherit the dark UI.

---

## ✅ 8. Quick Reference

| Environment       | Command                                                                                     | URL                     |
| ----------------- | ------------------------------------------------------------------------------------------- | ----------------------- |
| Local             | `python manage.py runserver`                                                                | `http://127.0.0.1:8000` |
| AWS EC2           | `python manage.py runserver 0.0.0.0:8000`                                                   | `http://<EC2-IP>:8000`  |
| Self-signed HTTPS | `python manage.py runserver_plus --cert-file server.crt --key-file server.key 0.0.0.0:8443` | `https://<EC2-IP>:8443` |


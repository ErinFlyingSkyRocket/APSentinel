# apsentinel/views.py
import json
import base64
import logging
from datetime import datetime
from typing import Optional

from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from django.utils import timezone as dj_timezone

from devices.models import Device
from evidence.models import AccessPointObservation  # UPDATED MODEL
from .crypto_utils import verify_ecdsa_p256_sha256
from .hashchain import compute_payload_hash, compute_chain_hash

logger = logging.getLogger("apsentinel")


def health(request):
    return JsonResponse({"status": "ok"})


def _parse_iso_dt(s: Optional[str]) -> Optional[datetime]:
    """
    Parse ISO8601 strings like '2025-10-31T07:05:12Z' or with timezone.
    Returns aware datetime in UTC if possible, else None.
    """
    if not s:
        return None
    try:
        # Accept trailing 'Z'
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        # Ensure aware
        if dt.tzinfo is None:
            return dj_timezone.make_aware(dt, dj_timezone.utc)
        return dt.astimezone(dj_timezone.utc)
    except Exception:
        return None


def _as_bytes(x):
    """
    Normalize DB-returned binary/hex to bytes for chain hashing.
    - If already bytes -> pass through
    - If memoryview -> convert to bytes
    - If hex string length 64 -> convert from hex
    - Else return as-is (may be None)
    """
    if x is None:
        return None
    if isinstance(x, bytes):
        return x
    if isinstance(x, memoryview):
        return bytes(x)
    if isinstance(x, str) and len(x) in (64, 40):  # sha256/sha1 hex len
        try:
            return bytes.fromhex(x)
        except ValueError:
            return x
    return x


@csrf_exempt
def ingest_observation(request):
    """
    Ingest an observation sent from an ESP32 (or any device) with signed data.
    Auto-activates the device and updates its last_seen timestamp upon
    successful signature verification.
    """
    if request.method != "POST":
        return HttpResponseBadRequest("POST required")

    # --- Parse JSON ---
    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    # --- Required fields ---
    required = ["device_name", "ssid", "bssid", "sensor_ts", "device_signature"]
    missing = [k for k in required if k not in data or not data[k]]
    if missing:
        return HttpResponseBadRequest(f"Missing fields: {', '.join(missing)}")

    device_name = data["device_name"]
    signature_b64 = data["device_signature"]

    # --- Find device ---
    try:
        device = Device.objects.get(name=device_name)
    except Device.DoesNotExist:
        return HttpResponseForbidden("Unknown device")

    # --- Canonicalize payload (exclude signature) ---
    to_sign = {
        "device_name": data["device_name"],
        "ssid": data["ssid"],
        "bssid": data["bssid"],
        "rsn": data.get("rsn"),
        "rssi": data.get("rssi"),
        "sensor_ts": data["sensor_ts"],
    }
    canonical = json.dumps(to_sign, separators=(",", ":"), sort_keys=True).encode("utf-8")

    # --- Verify signature ---
    if not verify_ecdsa_p256_sha256(device.pubkey_pem, canonical, signature_b64):
        logger.warning(f"[BAD_SIG] device={device_name} rejected invalid signature")
        return HttpResponseForbidden("Bad signature")

    # --- Auto-activate + update last_seen ---
    now = dj_timezone.now()
    fields_to_update = ["last_seen"]
    device.last_seen = now
    if not device.is_active:
        device.is_active = True
        fields_to_update.append("is_active")
    device.save(update_fields=fields_to_update)

    # --- Compute payload + chain hash ---
    payload_hash = compute_payload_hash(canonical)  # bytes or hex (your helper decides)
    server_ts = now  # store as datetime; stringify only for hashing input

    # Get previous chain hash for this device
    last = (
        AccessPointObservation.objects.filter(device=device)
        .order_by("-id")
        .values_list("chain_hash", flat=True)
        .first()
    )
    prev_chain_hash = _as_bytes(last)

    # If your compute_chain_hash expects strings, pass hex/iso strings accordingly.
    # Here we pass bytes for previous hash & payload hash, and ISO string for server_ts:
    chain_hash = compute_chain_hash(prev_chain_hash, payload_hash, server_ts.isoformat())

    # --- Parse sensor_ts ---
    sensor_ts = _parse_iso_dt(data.get("sensor_ts"))

    # --- Persist atomically ---
    with transaction.atomic():
        obs = AccessPointObservation.objects.create(
            device=device,
            ssid=data["ssid"],
            bssid=data["bssid"],
            # map RSN to the new model's 'security' field
            security=data.get("rsn"),
            rssi=data.get("rssi"),
            band=data.get("band"),
            channel=data.get("channel"),
            vendor_oui=data.get("vendor_oui"),
            source_device=device_name,

            # timestamps & chain
            sensor_ts=sensor_ts,
            server_ts=server_ts,
            payload_hash=_as_bytes(payload_hash),
            prev_chain_hash=_as_bytes(prev_chain_hash),
            chain_hash=_as_bytes(chain_hash),
            device_sig=base64.b64decode(signature_b64),
        )

    # --- Log successful ingest ---
    logger.info(
        "Observation stored | id=%s | device=%s | ssid=%s | bssid=%s | rssi=%s | sensor_ts=%s | server_ts=%s",
        obs.id,
        device.name,
        obs.ssid,
        obs.bssid,
        obs.rssi,
        data.get("sensor_ts"),
        server_ts.isoformat(),
    )

    return JsonResponse({"status": "ok", "obs_id": obs.id})

import json
import base64
import logging
from datetime import datetime, timezone
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from django.utils import timezone as dj_timezone

from devices.models import Device
from evidence.models import Observation
from .crypto_utils import verify_ecdsa_p256_sha256
from .hashchain import compute_payload_hash, compute_chain_hash

logger = logging.getLogger("apsentinel")


def health(request):
    return JsonResponse({"status": "ok"})


@csrf_exempt
def ingest_observation(request):
    """
    Ingest an observation sent from an ESP32 (or any device) with signed data.
    Auto-activates the device and updates its last_seen timestamp upon
    successful signature verification.
    """
    if request.method != "POST":
        return HttpResponseBadRequest("POST required")

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

    # --- Find device (by name only, no active check) ---
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
    payload_hash = compute_payload_hash(canonical)
    server_ts = now.isoformat()

    last = (
        Observation.objects.filter(device=device)
        .order_by("-id")
        .values_list("chain_hash", flat=True)
        .first()
    )
    prev_chain_hash = bytes(last) if last is not None else None
    chain_hash = compute_chain_hash(prev_chain_hash, payload_hash, server_ts)

    # --- Save observation atomically ---
    with transaction.atomic():
        obs = Observation.objects.create(
            device=device,
            ssid=data["ssid"],
            bssid=data["bssid"],
            rsn=data.get("rsn"),
            rssi=data.get("rssi"),
            sensor_ts=data["sensor_ts"],
            payload_hash=payload_hash,
            prev_chain_hash=prev_chain_hash,
            chain_hash=chain_hash,
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
        obs.sensor_ts,
        server_ts,
    )

    return JsonResponse({"status": "ok", "obs_id": obs.id})

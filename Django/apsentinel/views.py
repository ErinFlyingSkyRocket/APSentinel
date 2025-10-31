import json
import base64
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from django.utils import timezone

from devices.models import Device
from evidence.models import Observation
from .crypto_utils import verify_ecdsa_p256_sha256
from .hashchain import compute_payload_hash, compute_chain_hash

import logging
logger = logging.getLogger("apsentinel")


def health(request):
    return JsonResponse({"status": "ok"})


@csrf_exempt
def ingest_observation(request):
    if request.method != "POST":
        return HttpResponseBadRequest("POST required")

    # 1) Parse JSON
    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    # 2) Validate required fields
    required = ["device_name", "ssid", "bssid", "sensor_ts", "device_signature"]
    missing = [k for k in required if k not in data or data[k] in (None, "")]
    if missing:
        return HttpResponseBadRequest(f"Missing fields: {', '.join(missing)}")

    device_name = data["device_name"]
    signature_b64 = data["device_signature"]

    # 3) Fetch device (do NOT require is_active for Option A)
    try:
        device = Device.objects.get(name=device_name)
    except Device.DoesNotExist:
        return HttpResponseForbidden("Unknown device")

    # 4) Canonicalize payload (exclude signature)
    to_sign = {
        "device_name": data["device_name"],
        "ssid": data["ssid"],
        "bssid": data["bssid"],
        "rsn": data.get("rsn"),
        "rssi": data.get("rssi"),
        "sensor_ts": data["sensor_ts"],
    }
    canonical = json.dumps(to_sign, separators=(",", ":"), sort_keys=True).encode("utf-8")

    # 5) Verify signature
    if not verify_ecdsa_p256_sha256(device.pubkey_pem, canonical, signature_b64):
        logger.warning(f"[BAD_SIG] device={device_name} rejected invalid signature")
        return HttpResponseForbidden("Bad signature")

    # 6) Compute hash chain inputs
    payload_hash = compute_payload_hash(canonical)
    server_ts_iso = timezone.now().isoformat()

    # Previous chain head for this device (None if first)
    last = (
        Observation.objects.filter(device=device)
        .order_by("-id")
        .values_list("chain_hash", flat=True)
        .first()
    )
    prev_chain_hash = bytes(last) if last is not None else None
    chain_hash = compute_chain_hash(prev_chain_hash, payload_hash, server_ts_iso)

    # 7) Store observation + stamp last_seen (atomic)
    with transaction.atomic():
        obs = Observation.objects.create(
            device=device,
            ssid=data["ssid"],
            bssid=data["bssid"],
            rsn=data.get("rsn"),
            rssi=data.get("rssi"),
            sensor_ts=data["sensor_ts"],  # keep as provided (ISO string)
            payload_hash=payload_hash,
            prev_chain_hash=prev_chain_hash,
            chain_hash=chain_hash,
            device_sig=base64.b64decode(signature_b64),
        )

        # Option A: derive uptime -> update last_seen only
        device.last_seen = timezone.now()
        device.save(update_fields=["last_seen"])

    # 8) Log
    logger.info(
        "Observation stored | id=%s | device=%s | ssid=%s | bssid=%s | rssi=%s | sensor_ts=%s | server_ts=%s",
        obs.id,
        device.name,
        obs.ssid,
        obs.bssid,
        obs.rssi,
        obs.sensor_ts,
        getattr(obs, "server_ts", None).isoformat() if getattr(obs, "server_ts", None) else server_ts_iso,
    )

    return JsonResponse({"status": "ok", "obs_id": obs.id})

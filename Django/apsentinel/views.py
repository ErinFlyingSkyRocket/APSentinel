import json
import base64
from datetime import datetime, timezone
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
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

    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    # Required fields
    required = ["device_name", "ssid", "bssid", "sensor_ts", "device_signature"]
    missing = [k for k in required if k not in data or data[k] in (None, "")]
    if missing:
        return HttpResponseBadRequest(f"Missing fields: {', '.join(missing)}")

    device_name = data["device_name"]
    signature_b64 = data["device_signature"]

    # Fetch device + verify it's active
    try:
        device = Device.objects.get(name=device_name, is_active=True)
    except Device.DoesNotExist:
        return HttpResponseForbidden("Unknown or inactive device")

    # Canonicalize payload (exclude signature)
    to_sign = {
        "device_name": data["device_name"],
        "ssid": data["ssid"],
        "bssid": data["bssid"],
        "rsn": data.get("rsn"),
        "rssi": data.get("rssi"),
        "sensor_ts": data["sensor_ts"],
    }
    canonical = json.dumps(to_sign, separators=(",", ":"), sort_keys=True).encode("utf-8")

    # Verify signature
    if not verify_ecdsa_p256_sha256(device.pubkey_pem, canonical, signature_b64):
        logger.warning(f"[BAD_SIG] device={device_name} rejected invalid signature")
        return HttpResponseForbidden("Bad signature")

    # Compute hashes
    payload_hash = compute_payload_hash(canonical)
    server_ts = datetime.now(timezone.utc).isoformat()

    last = (
        Observation.objects.filter(device=device)
        .order_by("-id")
        .values_list("chain_hash", flat=True)
        .first()
    )
    prev_chain_hash = bytes(last) if last is not None else None
    chain_hash = compute_chain_hash(prev_chain_hash, payload_hash, server_ts)

    # Store observation
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

    # Log to console / file (INFO level)
    logger.info(
        "Observation stored | id=%s | device=%s | ssid=%s | bssid=%s | rssi=%s | sensor_ts=%s | server_ts=%s",
        obs.id,
        device.name,
        obs.ssid,
        obs.bssid,
        obs.rssi,
        obs.sensor_ts,
        obs.server_ts.isoformat() if hasattr(obs.server_ts, "isoformat") else server_ts,
    )

    return JsonResponse({"status": "ok", "obs_id": obs.id})

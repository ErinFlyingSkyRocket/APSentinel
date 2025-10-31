from django.http import JsonResponse, HttpResponseNotFound
from evidence.models import AccessPointObservation  # UPDATED


def latest_observation(request):
    try:
        o = AccessPointObservation.objects.latest("id")
    except AccessPointObservation.DoesNotExist:
        return HttpResponseNotFound("No observations")

    def to_hex(val):
        if not val:
            return None
        if isinstance(val, (bytes, bytearray)):
            return val.hex()
        if isinstance(val, memoryview):
            return bytes(val).hex()
        # if it's already a hex string, just return
        if isinstance(val, str):
            return val
        try:
            return bytes(val).hex()
        except Exception:
            return str(val)

    return JsonResponse({
        "id": o.id,
        "device": str(o.device) if o.device else None,
        "ssid": o.ssid,
        "bssid": o.bssid,
        "sensor_ts": o.sensor_ts.isoformat() if o.sensor_ts else None,
        "server_ts": o.server_ts.isoformat() if o.server_ts else None,
        "payload_hash": to_hex(o.payload_hash),
        "prev_chain_hash": to_hex(o.prev_chain_hash),
        "chain_hash": to_hex(o.chain_hash),
        "band": o.band,
        "channel": o.channel,
        "security": o.security,
        "rssi": o.rssi,
        "is_whitelisted": o.is_whitelisted,
        "is_flagged": o.is_flagged,
        "risk_score": o.risk_score,
    })

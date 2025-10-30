from django.http import JsonResponse, HttpResponseNotFound
from .models import Observation

def latest_observation(request):
    try:
        o = Observation.objects.latest("id")
    except Observation.DoesNotExist:
        return HttpResponseNotFound("No observations")
    to_hex = lambda b: (b if isinstance(b, (bytes, bytearray)) else bytes(b)).hex()
    return JsonResponse({
        "id": o.id,
        "device": str(o.device),
        "ssid": o.ssid,
        "bssid": o.bssid,
        "sensor_ts": o.sensor_ts.isoformat(),
        "server_ts": o.server_ts.isoformat(),
        "payload_hash": to_hex(o.payload_hash),
        "chain_hash": to_hex(o.chain_hash),
    })

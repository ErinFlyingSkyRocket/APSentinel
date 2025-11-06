# evidence/views.py
import json

from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from django.db.models import Q
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .models import (
    AccessPointObservation,
    AccessPointWhitelistGroup,
    AccessPointWhitelistEntry,
)

from devices.models import Device  # <-- to check is_active on ingest


def latest_observation(request):
    obs = (
        AccessPointObservation.objects
        .select_related("device", "matched_group", "matched_entry")
        .order_by("-server_ts")[:50]
    )
    return render(request, "evidence/latest_observation.html", {"observations": obs})


def whitelist_list(request):
    q = request.GET.get("q", "").strip()
    active = request.GET.get("active", "").strip()

    groups = (
        AccessPointWhitelistGroup.objects
        .prefetch_related("entries")
        .order_by("ssid", "name")
    )

    if q:
        groups = groups.filter(Q(ssid__icontains=q) | Q(name__icontains=q))

    if active == "1":
        groups = groups.filter(is_active=True)
    elif active == "0":
        groups = groups.filter(is_active=False)

    return render(
        request,
        "evidence/whitelist_list.html",
        {
            "groups": groups,
            "q": q,
            "active": active,
        },
    )


def whitelist_add(request):
    if request.method == "POST":
        name = request.POST.get("name") or request.POST.get("ssid") or "AP Group"
        ssid = request.POST.get("ssid", "").strip()
        location = request.POST.get("location", "").strip()
        default_security = request.POST.get("default_security", "").strip()
        strict = request.POST.get("strict") == "on"
        # read is_active checkbox
        is_active = "is_active" in request.POST

        grp = AccessPointWhitelistGroup.objects.create(
            name=name,
            ssid=ssid,
            location=location,
            default_security=default_security,
            strict=strict,
            is_active=is_active,
        )

        # optional: create one entry right away if user provided bssid
        bssid = request.POST.get("bssid", "").strip()
        if bssid:
            AccessPointWhitelistEntry.objects.create(
                group=grp,
                bssid=bssid,
                security=default_security or None,
                # entry will default to is_active=True from model
            )

        return redirect("whitelist_list")

    return render(request, "evidence/whitelist_add.html")


def whitelist_edit(request, pk):
    group = get_object_or_404(AccessPointWhitelistGroup, pk=pk)

    if request.method == "POST":
        group.name = request.POST.get("name", group.name)
        group.ssid = request.POST.get("ssid", group.ssid)
        group.location = request.POST.get("location", group.location)
        group.default_security = request.POST.get("default_security", group.default_security)
        # keep strict
        group.strict = request.POST.get("strict") == "on"
        # toggle active from checkbox
        group.is_active = "is_active" in request.POST
        group.updated_at = timezone.now()
        group.save()

        # handle adding new entry under this group
        new_bssid = request.POST.get("new_bssid", "").strip()
        if new_bssid:
            AccessPointWhitelistEntry.objects.create(
                group=group,
                bssid=new_bssid,
                security=request.POST.get("new_security", "").strip() or group.default_security,
                channel=request.POST.get("new_channel") or None,
                # entry active by default
            )

        return redirect("whitelist_edit", pk=group.pk)

    entries = group.entries.all().order_by("bssid")
    return render(
        request,
        "evidence/whitelist_edit.html",
        {
            "group": group,
            "entries": entries,
        },
    )


def whitelist_delete(request, pk):
    group = get_object_or_404(AccessPointWhitelistGroup, pk=pk)
    if request.method == "POST":
        group.delete()
        return redirect("whitelist_list")
    return render(request, "evidence/whitelist_delete.html", {"group": group})


def whitelist_entry_delete(request, pk):
    entry = get_object_or_404(AccessPointWhitelistEntry, pk=pk)
    group_id = entry.group_id
    entry.delete()
    return redirect("whitelist_edit", pk=group_id)


# ---------------------------------------------------------------------
# ESP32 / scanner ingest endpoint
# ---------------------------------------------------------------------
@csrf_exempt
def esp32_ingest(request):
    """
    Expected JSON (example):
    {
      "device_name": "scanner-01",
      "aps": [
        {
          "ssid": "Hospital-WiFi",
          "bssid": "AA:BB:CC:DD:EE:FF",
          "channel": 6,
          "band": "2.4GHz",
          "rssi_current": -55,
          "security": "WPA2-PSK"
        },
        ...
      ]
    }
    We will:
      1. check device exists
      2. check device.is_active == True
      3. if inactive, ignore
      4. else store observations
    """
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "invalid json"}, status=400)

    # 1) who sent this?
    device_name = payload.get("device_name") or request.headers.get("X-Device-Name")
    if not device_name:
        return JsonResponse({"error": "device_name missing"}, status=400)

    # 2) is this device allowed?
    device = Device.objects.filter(name=device_name).first()
    if not device or not device.is_active:
        # silently accept but do nothing
        return JsonResponse(
            {"status": "ignored", "reason": "device_inactive_or_unknown"},
            status=200,
        )

    # 3) mark device as seen
    device.last_seen = timezone.now()
    device.save(update_fields=["last_seen"])

    aps = payload.get("aps", [])
    created = 0

    for ap in aps:
        bssid = ap.get("bssid")
        if not bssid:
            continue

        AccessPointObservation.objects.create(
            device=device,
            ssid=ap.get("ssid") or None,
            bssid=bssid,
            oui=ap.get("oui") or None,
            channel=ap.get("channel") or 1,
            band=ap.get("band") or None,
            rssi_current=ap.get("rssi_current"),
            rssi_best=ap.get("rssi_best"),
            beacons=ap.get("beacons"),
            sensor_last_seen_ms=ap.get("last_seen_ms"),
            security=ap.get("security") or None,
            rsn_text=ap.get("rsn_text") or None,
            akm_list=ap.get("akm_list") or None,
            pmf_capable=ap.get("pmf_capable", False),
            pmf_required=ap.get("pmf_required", False),
            sensor_ts=timezone.now(),   # or parse from ap if you send it
            server_ts=timezone.now(),
        )
        created += 1

    return JsonResponse({"status": "ok", "created": created}, status=201)

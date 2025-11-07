# evidence/views.py
import json

from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from django.db.models import Q
from django.http import JsonResponse, HttpResponseBadRequest
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


@csrf_exempt
def esp32_ingest(request):
    # debug print
    if request.method == "POST":
        try:
            body_txt = request.body.decode("utf-8")
        except Exception:
            body_txt = "<decode failed>"
        print("=== /ingest/esp32/ CALLED ===")
        print("method:", request.method)
        print("path:", request.path)
        print("raw body:", body_txt)
        print("headers:", dict(request.headers))
        print("=== END CALL HEADER DUMP ===")
    else:
        return JsonResponse({"status": "alive", "detail": "send POST JSON here"}, status=200)

    # POST only
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    # parse JSON
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception as e:
        return JsonResponse({"error": "invalid json", "detail": str(e)}, status=400)

    # extract device identifiers
    device_block = payload.get("device") or {}
    device_mac_raw = device_block.get("mac") or ""
    device_name_raw = device_block.get("name") or ""
    # ESP sends colon MAC, user might have saved colon-less
    def norm(s: str) -> str:
        return (s or "").replace(":", "").replace("-", "").strip().upper()

    candidate_ids = [norm(device_mac_raw), norm(device_name_raw)]
    # also: user might have saved the MAC as-is (with colons), so add the raw too
    candidate_ids.append(device_mac_raw.strip())
    candidate_ids = [c for c in candidate_ids if c]
    print("[ingest] candidate identifiers from packet:", candidate_ids)

    # find active devices and try to match
    active_devices = list(
        Device.objects.filter(is_active=True).values("id", "name")
    )
    # build simple index {normalized_name: id}
    indexed = {}
    for d in active_devices:
      indexed[norm(d["name"])] = d["id"]

    print("[ingest] active devices in DB:", [
        {"id": d["id"], "name": d["name"], "name_norm": norm(d["name"])}
        for d in active_devices
    ])

    device = None
    for cid in candidate_ids:
        # try exact normalized name match
        if cid in indexed:
            device = Device.objects.get(pk=indexed[cid])
            break

    # fallback: if exactly 1 active device, just use it (your current prints show this case)
    if device is None:
        if len(active_devices) == 1:
            device = Device.objects.get(pk=active_devices[0]["id"])
            print("[ingest] no exact match, but exactly 1 active device -> using it")
        else:
            print("[ingest] device unknown or inactive, ignoring.")
            return JsonResponse(
                {"status": "ignored", "reason": "device_inactive_or_unknown"},
                status=200,
            )

    # update device last_seen
    device.last_seen = timezone.now()
    device.save(update_fields=["last_seen"])

    # observations array (ESP32 format)
    records = payload.get("observations") or []
    created = 0

    for rec in records:
        bssid = rec.get("bssid")
        ssid = rec.get("ssid") or None
        if not bssid:
            continue

        # ---- whitelist matching ----
        matched_entry = None
        matched_group = None

        # 1) try BSSID entry match (exact BSSID, active group)
        matched_entry = (
            AccessPointWhitelistEntry.objects.select_related("group")
            .filter(
                bssid__iexact=bssid,
                group__is_active=True,
            )
            .first()
        )
        if matched_entry:
            matched_group = matched_entry.group
        else:
            # 2) fallback: match by SSID to an active group
            if ssid:
                matched_group = (
                    AccessPointWhitelistGroup.objects
                    .filter(is_active=True, ssid__iexact=ssid)
                    .first()
                )

        # if the group is strict, we skip storing this safe AP
        if matched_group and matched_group.strict:
            # just skip creation
            continue

        pmf_obj = rec.get("pmf") or {}

        AccessPointObservation.objects.create(
            device=device,
            ssid=ssid,
            bssid=bssid,
            oui=rec.get("oui") or None,
            channel=rec.get("ch") or rec.get("channel") or 1,
            band=None,
            rssi_current=rec.get("rssi_cur") or rec.get("rssi_current"),
            rssi_best=rec.get("rssi_best"),
            beacons=rec.get("beacons"),
            sensor_last_seen_ms=rec.get("last_seen_ms"),
            security=rec.get("security") or None,
            rsn_text=rec.get("rsn") or rec.get("rsn_text"),
            akm_list=rec.get("akm") or rec.get("akm_list"),
            pmf_capable=pmf_obj.get("cap", False) or rec.get("pmf_capable", False),
            pmf_required=pmf_obj.get("req", False) or rec.get("pmf_required", False),
            sensor_ts=timezone.now(),
            server_ts=timezone.now(),
            matched_group=matched_group,
            matched_entry=matched_entry,
        )
        created += 1

    return JsonResponse({"status": "ok", "created": created}, status=201)
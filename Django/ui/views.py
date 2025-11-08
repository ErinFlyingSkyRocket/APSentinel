# ui/views.py
from datetime import timedelta
import csv

from django.shortcuts import render, get_object_or_404
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.utils.dateparse import parse_date
from django.contrib.auth.decorators import login_required
from django.db.models import Q, Max
from django.utils import timezone

from devices.models import Device
from evidence.models import AccessPointObservation


@login_required
def dashboard(request):
    now = timezone.now()
    cutoff_10m = now - timedelta(minutes=10)
    cutoff_1h = now - timedelta(hours=1)

    # --- counts for the top cards ---
    total_obs = AccessPointObservation.objects.count()
    total_devices = Device.objects.count()

    # --- active/offline devices (last seen ≤ 1h) ---
    # get latest observation per device
    latest_obs_by_device = (
        AccessPointObservation.objects
        .values("device_id")
        .annotate(last_seen=Max("server_ts"))
    )
    device_last_seen = {row["device_id"]: row["last_seen"] for row in latest_obs_by_device}

    device_rows = []
    active_count = 0
    for dev in Device.objects.order_by("name"):
        last_seen = device_last_seen.get(dev.id)
        if last_seen and last_seen >= cutoff_1h:
            status = "online"
            active_count += 1
        else:
            status = "offline"
        device_rows.append({
            "device": dev,
            "last_seen": last_seen,
            "status": status,
        })

    # --- unwhitelisted APs in last 10 min ---
    recent_flagged = (
        AccessPointObservation.objects
        .select_related("device")
        .filter(is_flagged=True, server_ts__gte=cutoff_10m)
        .order_by("-server_ts")
    )

    current_unwhitelisted = []
    seen = set()
    for o in recent_flagged:
        key = o.bssid or f"ssid:{o.ssid}"
        if key in seen:
            continue
        seen.add(key)
        current_unwhitelisted.append(o)

    # --- recent alerts (short list) ---
    recent_alerts = (
        AccessPointObservation.objects
        .filter(is_flagged=True)
        .select_related("device")
        .order_by("-server_ts")[:20]
    )

    return render(
        request,
        "ui/dashboard.html",
        {
            "total_obs": total_obs,
            "active_device_count": active_count,
            "device_rows": device_rows,
            "current_unwhitelisted": current_unwhitelisted,
            "recent_alerts": recent_alerts,
        },
    )

@login_required
def observations(request):
    """
    Main observations page:
    - filterable, exportable main log (big table)  -> own paginator (?page=)
    - 10-min flagged (current_unwhitelisted)       -> own paginator (?flag_page=)
    - all flagged / recent alerts                  -> own paginator (?alert_page=)
    """

    # ----------------------
    # 1) MAIN FILTERED QUERY
    # ----------------------
    qs = (
        AccessPointObservation.objects
        .select_related("device", "matched_group", "matched_entry")
        .order_by("-server_ts")
    )

    # --- filters ---
    q = request.GET.get("q") or ""
    if q:
        qs = qs.filter(Q(ssid__icontains=q) | Q(bssid__icontains=q))

    device_id = request.GET.get("device")
    if device_id:
        qs = qs.filter(device_id=device_id)

    since = request.GET.get("since")
    if since:
        d = parse_date(since)
        if d:
            qs = qs.filter(server_ts__date__gte=d)

    until = request.GET.get("until")
    if until:
        d = parse_date(until)
        if d:
            qs = qs.filter(server_ts__date__lte=d)

    # --- CSV export still uses the filtered qs ---
    if request.GET.get("export") == "csv":
        resp = HttpResponse(content_type="text/csv")
        resp["Content-Disposition"] = "attachment; filename=observations.csv"
        w = csv.writer(resp)
        w.writerow([
            "id",
            "server_ts",
            "device",
            "ssid",
            "bssid",
            "channel",
            "security",
            "rssi_current",
            "match_status",
        ])
        for o in qs.iterator():
            w.writerow([
                o.id,
                o.server_ts.isoformat() if o.server_ts else "",
                o.device.name if o.device else "",
                o.ssid or "",
                o.bssid or "",
                o.channel or "",
                o.security or "",
                o.rssi_current if o.rssi_current is not None else "",
                o.match_status or "",
            ])
        return resp

    # ----------------------
    # 2) SIDE TABLE 1: 10-min flagged
    # ----------------------
    now = timezone.now()
    cutoff = now - timedelta(minutes=10)
    flagged_10min_qs = (
        AccessPointObservation.objects
        .filter(is_flagged=True, server_ts__gte=cutoff)
        .select_related("device")
        .order_by("-server_ts")
    )
    flag_paginator = Paginator(flagged_10min_qs, 10)
    flag_page_number = request.GET.get("flag_page")
    flag_page = flag_paginator.get_page(flag_page_number)

    # ----------------------
    # 3) SIDE TABLE 2: recent alerts (all flagged)
    # ----------------------
    alerts_qs = (
        AccessPointObservation.objects
        .filter(is_flagged=True)
        .select_related("device")
        .order_by("-server_ts")
    )
    alerts_paginator = Paginator(alerts_qs, 10)
    alert_page_number = request.GET.get("alert_page")
    alert_page = alerts_paginator.get_page(alert_page_number)

    # ----------------------
    # 4) MAIN TABLE PAGINATION
    # ----------------------
    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get("page"))

    # keep other query params when changing page (for the main table)
    keep = request.GET.copy()
    if "page" in keep:
        del keep["page"]
    keepqs = keep.urlencode()

    devices = Device.objects.order_by("name").only("id", "name")

    return render(
        request,
        "ui/observations.html",
        {
            # main, filterable table
            "page": page,
            "keepqs": keepqs,
            "devices": devices,
            "q": q,
            "selected_device": device_id,
            "since": since,
            "until": until,

            # side-by-side tables (each paginated)
            "flag_page": flag_page,
            "alert_page": alert_page,
        },
    )


@login_required
def observations_unwhitelisted(request):
    """
    List only observations that did NOT match any active whitelist.
    This is the page the "View suspicious" button links to.
    """
    qs = (
        AccessPointObservation.objects
        .filter(matched_group__isnull=True)
        .select_related("device")
        .order_by("-server_ts")
    )

    paginator = Paginator(qs, 25)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    return render(
        request,
        "ui/observations_unwhitelisted.html",
        {"page_obj": page_obj},
    )


@login_required
def observation_detail(request, pk: int):
    o = get_object_or_404(
        AccessPointObservation.objects.select_related("device", "matched_group", "matched_entry"),
        pk=pk,
    )
    return render(
        request,
        "ui/observation_detail.html",
        {
            "o": o,
            "canonical": o.canonical,
            "hash_sha256": o.hash_sha256,
            "sig_alg": o.sig_alg,
            "sig_r": o.sig_r,
            "sig_s": o.sig_s,
        },
    )

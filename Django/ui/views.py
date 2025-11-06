from datetime import timedelta
from django.shortcuts import render, get_object_or_404, redirect
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.utils.dateparse import parse_date
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.utils import timezone
from devices.models import Device
from evidence.models import AccessPointObservation
import csv

@login_required
def dashboard(request):
    now = timezone.now()
    cutoff = now - timedelta(minutes=5)  # Set "currently detected" window to 5 minutes

    # 1) Current detected unwhitelisted (flagged + recent + deduplicated by BSSID or SSID)
    recent_flagged = (
        AccessPointObservation.objects
        .select_related("device")
        .filter(is_flagged=True, server_ts__gte=cutoff)
        .order_by("-server_ts")
    )

    current_unwhitelisted = []
    seen = set()
    for o in recent_flagged:
        # Prefer BSSID, fall back to SSID if no BSSID exists
        key = o.bssid or f"ssid:{o.ssid}"
        if key in seen:
            continue
        seen.add(key)
        current_unwhitelisted.append(o)

    # 2) Recent alert logs / recent observations (everything)
    latest_logs = (
        AccessPointObservation.objects
        .select_related("device")
        .order_by("-server_ts")[:50]
    )

    # 3) All AP logs regardless of whitelist status (all detected APs)
    all_logs = (
        AccessPointObservation.objects
        .select_related("device")
        .order_by("-server_ts")
    )

    counts = {
        "observations": AccessPointObservation.objects.count(),
        "active_devices": Device.objects.filter(is_active=True).count(),
    }
    
    last = latest_logs[0] if latest_logs else None

    return render(
        request,
        "ui/dashboard.html",
        {
            "last": last,
            "counts": counts,
            "current_unwhitelisted": current_unwhitelisted,
            "latest_logs": latest_logs,
            "all_logs": all_logs,  # For all detected APs, regardless of whitelist
            "cutoff_minutes": 5,
        },
    )


@login_required
def observations(request):
    # Start with all AccessPointObservation objects
    qs = AccessPointObservation.objects.select_related("device", "matched_group", "matched_entry").order_by("-server_ts")

    # Text search (for SSID / BSSID)
    q = request.GET.get("q") or ""
    if q:
        qs = qs.filter(Q(ssid__icontains=q) | Q(bssid__icontains=q))

    # Filter by device
    device_id = request.GET.get("device")
    if device_id:
        qs = qs.filter(device_id=device_id)

    # Date range filter (using server_ts date)
    since = request.GET.get("since")
    until = request.GET.get("until")
    if since:
        d = parse_date(since)
        if d:
            qs = qs.filter(server_ts__date__gte=d)
    if until:
        d = parse_date(until)
        if d:
            qs = qs.filter(server_ts__date__lte=d)

    # CSV export
    if request.GET.get("export") == "csv":
        resp = HttpResponse(content_type="text/csv")
        resp["Content-Disposition"] = "attachment; filename=observations.csv"
        w = csv.writer(resp)
        w.writerow([
            "id", "server_ts", "device", "ssid", "bssid", "channel", "security", "rssi_current", "match_status"
        ])
        for o in qs.iterator():
            w.writerow([
                o.id, o.server_ts.isoformat() if o.server_ts else "",
                o.device.name if o.device else "", o.ssid or "", o.bssid or "",
                o.channel or "", o.security or "", o.rssi_current if o.rssi_current is not None else "", o.match_status or ""
            ])
        return resp

    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get("page"))

    keep = request.GET.copy()
    if "page" in keep:
        del keep["page"]
    keepqs = keep.urlencode()

    devices = Device.objects.order_by("name").only("id", "name")
    return render(
        request,
        "ui/observations.html",
        {
            "page": page,
            "devices": devices,
            "keepqs": keepqs,
        },
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


@login_required
def devices_view(request):
    return render(
        request,
        "ui/devices.html",
        {"devices": Device.objects.order_by("name")},
    )

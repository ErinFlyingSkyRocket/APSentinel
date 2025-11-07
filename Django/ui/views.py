# ui/views.py
from datetime import timedelta
import csv

from django.shortcuts import render, get_object_or_404
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.utils.dateparse import parse_date
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.utils import timezone

from devices.models import Device
from evidence.models import AccessPointObservation


@login_required
def dashboard(request):
    # make dashboard + observations consistent: 10-minute “currently seen” window
    now = timezone.now()
    cutoff = now - timedelta(minutes=10)

    recent_flagged = (
        AccessPointObservation.objects
        .select_related("device")
        .filter(is_flagged=True, server_ts__gte=cutoff)
        .order_by("-server_ts")
    )

    # dedupe by BSSID (or SSID fallback)
    current_unwhitelisted = []
    seen = set()
    for o in recent_flagged:
        key = o.bssid or f"ssid:{o.ssid}"
        if key in seen:
            continue
        seen.add(key)
        current_unwhitelisted.append(o)

    latest_logs = (
        AccessPointObservation.objects
        .select_related("device")
        .order_by("-server_ts")[:50]
    )

    counts = {
        "observations": AccessPointObservation.objects.count(),
        "active_devices": Device.objects.filter(is_active=True).count(),
    }

    return render(
        request,
        "ui/dashboard.html",
        {
            "counts": counts,
            "current_unwhitelisted": current_unwhitelisted,
            "latest_logs": latest_logs,
        },
    )


@login_required
def observations(request):
    # base queryset
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

    # --- CSV export ---
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

    # --- data for the top 2 cards ---
    now = timezone.now()
    cutoff = now - timedelta(minutes=10)

    current_unwhitelisted = (
        AccessPointObservation.objects
        .filter(is_flagged=True, server_ts__gte=cutoff)
        .order_by("-server_ts")
    )

    recent_alerts = (
        AccessPointObservation.objects
        .filter(is_flagged=True)
        .order_by("-server_ts")[:15]
    )

    # --- pagination for main log ---
    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get("page"))

    # keep other query params when changing page
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
            "current_unwhitelisted": current_unwhitelisted,
            "recent_alerts": recent_alerts,
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

# ui/views.py
from django.shortcuts import render, get_object_or_404, redirect
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.utils.dateparse import parse_date
from django.contrib.auth.decorators import login_required
from django.db.models import Q

from devices.models import Device
from evidence.models import AccessPointObservation  # UPDATED MODEL
from .forms import DeviceForm

import csv


@login_required
def dashboard(request):
    last = (
        AccessPointObservation.objects
        .select_related("device")
        .order_by("-id")
        .first()
    )
    counts = {
        "observations": AccessPointObservation.objects.count(),
        "active_devices": Device.objects.filter(is_active=True).count(),
    }
    return render(request, "ui/dashboard.html", {"last": last, "counts": counts})


@login_required
def observations(request):
    qs = (
        AccessPointObservation.objects
        .select_related("device")
        .order_by("-id")
    )

    # Text search
    q = request.GET.get("q") or ""
    if q:
        qs = qs.filter(Q(ssid__icontains=q) | Q(bssid__icontains=q))

    # Filter by device
    device_id = request.GET.get("device")
    if device_id:
        qs = qs.filter(device_id=device_id)

    # Date range (by server_ts date)
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
        w.writerow(["id", "server_ts", "device", "ssid", "bssid", "rssi"])
        for o in qs.iterator():
            w.writerow([
                o.id,
                o.server_ts.isoformat() if o.server_ts else "",
                o.device.name if o.device else "",
                o.ssid or "",
                o.bssid or "",
                o.rssi if o.rssi is not None else "",
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
        {"page": page, "devices": devices, "keepqs": keepqs},
    )


@login_required
def observation_detail(request, pk: int):
    o = get_object_or_404(
        AccessPointObservation.objects.select_related("device"),
        pk=pk
    )

    def tohex(val):
        if not val:
            return None
        if isinstance(val, (bytes, bytearray)):
            return val.hex()
        # Some DB backends can return memoryview for BinaryField
        try:
            from collections.abc import Iterable
            if isinstance(val, memoryview):
                return bytes(val).hex()
            # If value is already hex string, return as-is
            if isinstance(val, str):
                return val
            # Fallback: try bytes() conversion
            return bytes(val).hex()
        except Exception:
            return str(val)

    ctx = {
        "o": o,
        "payload_hex": tohex(o.payload_hash),
        "prev_hex": tohex(o.prev_chain_hash),
        "chain_hex": tohex(o.chain_hash),
    }
    return render(request, "ui/observation_detail.html", ctx)


@login_required
def devices_view(request):
    return render(
        request,
        "ui/devices.html",
        {"devices": Device.objects.order_by("name")},
    )


@login_required
def add_device(request):
    if request.method == "POST":
        form = DeviceForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("/ui/devices")
    else:
        form = DeviceForm()
    return render(request, "ui/add_device.html", {"form": form})

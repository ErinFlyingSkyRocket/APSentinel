from django.shortcuts import render, get_object_or_404
from django.core.paginator import Paginator
from django.http import HttpResponse
from devices.models import Device
from evidence.models import Observation
from django.utils.dateparse import parse_date
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from .forms import DeviceForm
from django.db.models import Q


import csv

@login_required
def dashboard(request):
    last = Observation.objects.select_related("device").order_by("-id").first()
    counts = {
        "observations": Observation.objects.count(),
        "active_devices": Device.objects.filter(is_active=True).count(),
    }
    return render(request, "ui/dashboard.html", {"last": last, "counts": counts})

@login_required
def observations(request):
    qs = Observation.objects.select_related("device").order_by("-id")
    q = request.GET.get("q") or ""
    if q:
        qs = qs.filter(Q(ssid__icontains=q) | Q(bssid__icontains=q))
    device_id = request.GET.get("device")
    if device_id:
        qs = qs.filter(device_id=device_id)
    since = request.GET.get("since")
    until = request.GET.get("until")
    if since:
        d = parse_date(since)
        if d: qs = qs.filter(server_ts__date__gte=d)
    if until:
        d = parse_date(until)
        if d: qs = qs.filter(server_ts__date__lte=d)

    # CSV export
    if request.GET.get("export") == "csv":
        resp = HttpResponse(content_type="text/csv")
        resp["Content-Disposition"] = "attachment; filename=observations.csv"
        w = csv.writer(resp)
        w.writerow(["id","server_ts","device","ssid","bssid","rssi"])
        for o in qs.iterator():
            w.writerow([o.id, o.server_ts, o.device.name, o.ssid, o.bssid, o.rssi or ""])
        return resp

    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get("page"))
    keep = request.GET.copy()
    if "page" in keep: del keep["page"]
    keepqs = keep.urlencode()
    devices = Device.objects.order_by("name").only("id","name")
    return render(request, "ui/observations.html", {"page": page, "devices": devices, "keepqs": keepqs})

@login_required
def observation_detail(request, pk: int):
    o = get_object_or_404(Observation.objects.select_related("device"), pk=pk)
    tohex = lambda b: (b if isinstance(b,(bytes,bytearray)) else bytes(b)).hex() if b else None
    ctx = {
        "o": o,
        "payload_hex": tohex(o.payload_hash),
        "prev_hex": tohex(o.prev_chain_hash),
        "chain_hex": tohex(o.chain_hash),
    }
    return render(request, "ui/observation_detail.html", ctx)

@login_required
def devices_view(request):
    return render(request, "ui/devices.html", {"devices": Device.objects.order_by("name")})

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
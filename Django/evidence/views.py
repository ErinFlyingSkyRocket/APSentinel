from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse, HttpResponseNotFound, HttpResponseBadRequest
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_http_methods

from .models import AccessPointWhitelist, AccessPointObservation
from .forms import AccessPointWhitelistForm


# ---------- API (latest observation) ----------
@login_required
def latest_observation(request):
    """
    Return the most recent AccessPointObservation as JSON.
    This version matches your current model (no FK to Device).
    """
    try:
        o = AccessPointObservation.objects.latest("id")
    except AccessPointObservation.DoesNotExist:
        return HttpResponseNotFound("No observations")

    to_hex = lambda b: (b if isinstance(b, (bytes, bytearray)) else bytes(b)).hex() if b else None

    return JsonResponse({
        "id": o.id,
        "ssid": o.ssid,
        "bssid": o.bssid,
        "sensor_ts": o.first_seen.isoformat() if o.first_seen else None,
        "server_ts": o.updated_at.isoformat() if o.updated_at else None,
        "payload_hash": to_hex(getattr(o, "payload_hash", None)),  # present only if you added these fields
        "chain_hash": to_hex(getattr(o, "chain_hash", None)),
    })


# ---------- Whitelist: List ----------
@login_required
def whitelist_list(request):
    """
    List + simple search for whitelisted APs.
    Template: templates/evidence/whitelist_list.html
    """
    qs = AccessPointWhitelist.objects.all().order_by("-updated_at", "-id")

    q = (request.GET.get("q") or "").strip()
    if q:
        qs = qs.filter(ssid__icontains=q)

    active = request.GET.get("active")
    if active in {"1", "0"}:
        qs = qs.filter(active=(active == "1"))

    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get("page"))

    return render(request, "evidence/whitelist_list.html", {"page": page, "q": q, "active": active})


# ---------- Whitelist: Add ----------
@login_required
@require_http_methods(["GET", "POST"])
def whitelist_add(request):
    """
    Create a whitelist entry.
    Template: templates/evidence/whitelist_form.html
    """
    if request.method == "POST":
        form = AccessPointWhitelistForm(request.POST)
        if form.is_valid():
            obj = form.save()
            messages.success(request, f"Whitelisted “{obj.ssid}” created.")
            return redirect("/ui/whitelist")
        messages.error(request, "Please correct the errors below.")
    else:
        form = AccessPointWhitelistForm()

    return render(request, "evidence/whitelist_form.html", {"form": form, "mode": "add"})


# ---------- Whitelist: Edit ----------
@login_required
@require_http_methods(["GET", "POST"])
def whitelist_edit(request, pk: int):
    """
    Edit a whitelist entry.
    Template: templates/evidence/whitelist_form.html
    """
    obj = get_object_or_404(AccessPointWhitelist, pk=pk)

    if request.method == "POST":
        form = AccessPointWhitelistForm(request.POST, instance=obj)
        if form.is_valid():
            obj = form.save()
            messages.success(request, f"Whitelisted “{obj.ssid}” updated.")
            return redirect("/ui/whitelist")
        messages.error(request, "Please correct the errors below.")
    else:
        form = AccessPointWhitelistForm(instance=obj)

    return render(request, "evidence/whitelist_form.html", {"form": form, "mode": "edit", "obj": obj})


# ---------- Whitelist: Delete ----------
@login_required
@require_http_methods(["POST"])
def whitelist_delete(request, pk: int):
    """
    Delete a whitelist entry (POST only).
    Trigger via a small form/button in the list page.
    """
    obj = get_object_or_404(AccessPointWhitelist, pk=pk)
    name = obj.ssid
    obj.delete()
    messages.success(request, f"Whitelisted “{name}” deleted.")
    return redirect("/ui/whitelist")

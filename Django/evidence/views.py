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
        # --- update group fields ---
        group.name = request.POST.get("name", group.name)
        group.ssid = request.POST.get("ssid", group.ssid)
        group.location = request.POST.get("location", group.location)
        group.default_security = request.POST.get(
            "default_security", group.default_security
        )
        group.strict = request.POST.get("strict") == "on"
        group.is_active = "is_active" in request.POST
        group.updated_at = timezone.now()
        group.save()

        # --- handle adding new entry under this group (optional) ---
        new_bssid = request.POST.get("new_bssid", "").strip()

        if new_bssid:
            new_security = request.POST.get("new_security", "").strip()
            new_channel = request.POST.get("new_channel") or None
            new_band = request.POST.get("new_band", "").strip() or None
            new_vendor_oui = request.POST.get("new_vendor_oui", "").strip() or None
            new_rsn_text = request.POST.get("new_rsn_text", "").strip() or None
            new_akm_list = request.POST.get("new_akm_list", "").strip() or None

            AccessPointWhitelistEntry.objects.create(
                group=group,
                bssid=new_bssid,
                security=new_security or group.default_security or None,
                channel=new_channel,
                band=new_band,
                vendor_oui=new_vendor_oui,
                rsn_text=new_rsn_text,
                akm_list=new_akm_list,
                # pmf_capable / pmf_required / is_active use model defaults
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

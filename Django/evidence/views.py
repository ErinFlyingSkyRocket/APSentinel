# evidence/views.py
import json

from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from django.db.models import Q
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required


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

@login_required
def whitelist_add_from_observation(request, obs_id):
    """
    Shortcut: take one UNREGISTERED_AP observation and
    turn it into a whitelist entry.

    Behaviour:
      - Find (or create) a whitelist group for this SSID.
      - Add/activate a whitelist entry for this BSSID with
        the current security / RSN / AKM / OUI / band info.
      - Redirect to whitelist_edit so the user can fine-tune.
    """
    if request.method != "POST":
        # Only allow via POST (button form)
        return redirect("unregistered_aps")

    obs = get_object_or_404(AccessPointObservation, pk=obs_id)

    ssid = (obs.ssid or "").strip()
    if not ssid:
        # Hidden SSIDs are awkward to manage as groups; just bail out to the list.
        return redirect("unregistered_aps")

    # ------------------------------------------------------------------
    # 1) Find or create a group for this SSID
    # ------------------------------------------------------------------
    group = (
        AccessPointWhitelistGroup.objects
        .filter(ssid=ssid, is_active=True)
        .order_by("id")
        .first()
    )

    if not group:
        # First time we see this SSID: create an "auto" group
        group_name = f"Auto: {ssid}"
        group = AccessPointWhitelistGroup.objects.create(
            name=group_name[:128],
            ssid=ssid,
            location="",
            default_security=obs.security or "",
            strict=True,   # you can flip this to False if you prefer non-strict defaults
            is_active=True,
        )

    # ------------------------------------------------------------------
    # 2) Create / update entry for this specific BSSID under that group
    # ------------------------------------------------------------------
    vendor_oui = (obs.oui or "").upper() if obs.oui else None

    entry, created = AccessPointWhitelistEntry.objects.get_or_create(
        group=group,
        bssid=obs.bssid,
        defaults={
            "security": obs.security or group.default_security,
            "channel": obs.channel,
            "band": obs.band,
            "vendor_oui": vendor_oui,
            "rsn_text": obs.rsn_text or None,
            "akm_list": obs.akm_list or None,
            "pmf_capable": bool(obs.pmf_capable),
            "pmf_required": bool(obs.pmf_required),
            "is_active": True,
        },
    )

    if not created:
        # If an entry already exists for this BSSID, we:
        # - ensure it's active
        # - only fill blanks with fresh data (don't silently override existing choices)
        changed = False

        if not entry.is_active:
            entry.is_active = True
            changed = True

        field_updates = [
            ("security", obs.security or group.default_security),
            ("channel", obs.channel),
            ("band", obs.band),
            ("vendor_oui", vendor_oui),
            ("rsn_text", obs.rsn_text),
            ("akm_list", obs.akm_list),
        ]
        for field, value in field_updates:
            if value not in (None, "", 0) and getattr(entry, field) in (None, "", 0):
                setattr(entry, field, value)
                changed = True

        if changed:
            entry.save()

    # After adding, jump straight to the group editor so user can refine.
    return redirect("whitelist_edit", pk=group.pk)

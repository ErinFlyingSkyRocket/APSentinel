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
from apsentinel.views import _match_whitelist  # dynamic whitelist check


def _attach_dynamic_status(obs):
    """
    Attach dynamic whitelist status to a single observation instance.
    This ALWAYS uses the current whitelist table.

    dynamic_flagged:
      - True if the AP is anything other than strongly/weakly whitelisted.

    dynamic_anomaly:
      - True for "evil-twin-style" anomalies within a known SSID environment:
          * CHANNEL_MISMATCH
          * SECURITY_MISMATCH
          * VENDOR_MISMATCH
          * BAND_MISMATCH
          * RSN_MISMATCH
          * AKM_MISMATCH
          * PMF_MISMATCH
          * KNOWN_SSID_BUT_UNEXPECTED_AP
          * KNOWN_SSID_REJECTED
      - UNREGISTERED_AP is *not* treated as anomaly here (handled by other tables).
    """
    ssid = obs.ssid or ""
    bssid = obs.bssid or ""
    security = obs.security
    channel = obs.channel or 0
    oui = obs.oui or ""

    # richer fields for more specific evil-twin detection
    band = getattr(obs, "band", None)
    rsn_text = getattr(obs, "rsn_text", None)
    akm_list = getattr(obs, "akm_list", None)
    pmf_capable = getattr(obs, "pmf_capable", None)
    pmf_required = getattr(obs, "pmf_required", None)

    grp, entry, status = _match_whitelist(
        ssid=ssid,
        bssid=bssid,
        security=security,
        channel=channel,
        oui=oui,
        band=band,
        rsn_text=rsn_text,
        akm_list=akm_list,
        pmf_capable=pmf_capable,
        pmf_required=pmf_required,
    )

    # attach transient attributes for templates
    obs.dynamic_group = grp
    obs.dynamic_entry = entry
    obs.dynamic_status = status

    # flagged if NOT strongly/weakly whitelisted
    obs.dynamic_flagged = status not in ("WHITELISTED_STRONG", "WHITELISTED_WEAK")

    # "evil twin / whitelist anomaly" only for known SSID situations
    obs.dynamic_anomaly = status in (
        "CHANNEL_MISMATCH",
        "SECURITY_MISMATCH",
        "VENDOR_MISMATCH",
        "BAND_MISMATCH",
        "RSN_MISMATCH",
        "AKM_MISMATCH",
        "PMF_MISMATCH",
        "KNOWN_SSID_BUT_UNEXPECTED_AP",
        "KNOWN_SSID_REJECTED",
    )

    return obs


# ---------------------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------------------
@login_required
def dashboard(request):
    now = timezone.now()
    cutoff_10m = now - timedelta(minutes=10)
    cutoff_1h = now - timedelta(hours=1)

    # --- counts for the top cards ---
    total_obs = AccessPointObservation.objects.count()
    total_devices = Device.objects.count()

    # --- active/offline devices (last seen ≤ 1h) ---
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

    # --- current unwhitelisted APs in last 10 min (dynamic against whitelist) ---
    recent_obs_10m = (
        AccessPointObservation.objects
        .select_related("device")
        .filter(server_ts__gte=cutoff_10m)
        .order_by("-server_ts")
    )

    current_unwhitelisted = []
    seen = set()
    for o in recent_obs_10m:
        _attach_dynamic_status(o)
        # needs to be NOT whitelisted
        if not o.dynamic_flagged:
            continue

        # de-duplicate by BSSID / SSID
        key = o.bssid or f"ssid:{o.ssid}"
        if key in seen:
            continue
        seen.add(key)
        current_unwhitelisted.append(o)

    # --- recent alerts (dynamic; last 200 obs, pick ones flagged) ---
    recent_obs = (
        AccessPointObservation.objects
        .select_related("device")
        .order_by("-server_ts")[:200]
    )
    recent_alerts = []
    for o in recent_obs:
        _attach_dynamic_status(o)
        if o.dynamic_flagged:
            recent_alerts.append(o)
        if len(recent_alerts) >= 20:
            break

    # --- CRITICAL: whitelist anomalies / possible evil twins (last 60 min) ---
    anomalies_qs = (
        AccessPointObservation.objects
        .select_related("device")
        .filter(server_ts__gte=cutoff_1h)
        .order_by("-server_ts")
    )

    anomalies_critical = []
    for o in anomalies_qs:
        _attach_dynamic_status(o)
        if o.dynamic_anomaly:
            anomalies_critical.append(o)
    # Optionally cap, e.g.: anomalies_critical = anomalies_critical[:100]

    return render(
        request,
        "ui/dashboard.html",
        {
            "total_obs": total_obs,
            "total_devices": total_devices,
            "active_device_count": active_count,
            "device_rows": device_rows,
            "current_unwhitelisted": current_unwhitelisted,
            "recent_alerts": recent_alerts,
            "anomalies_critical": anomalies_critical,
        },
    )


# ---------------------------------------------------------------------
# OBSERVATIONS (main page)
# ---------------------------------------------------------------------
@login_required
def observations(request):
    """
    Main observations page (fully dynamic vs current whitelist):

    - Main log table is filterable and uses dynamic whitelist status.
    - 10-min flagged table recomputes dynamic_flagged each load.
    - Recent alerts table recomputes dynamic_flagged each load.
    - Whitelist anomalies table recomputes dynamic_anomaly each load.
    - Each of the 3 small tables has its own SSID/BSSID search:
        flag_q, alert_q, anomaly_q.
    """

    # ----------------------
    # 1) MAIN FILTERED QUERY
    # ----------------------
    qs = (
        AccessPointObservation.objects
        .select_related("device", "matched_group", "matched_entry")
        .order_by("-server_ts")
    )

    # --- main filters ---
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

    # per-table search terms
    flag_q = request.GET.get("flag_q") or ""
    alert_q = request.GET.get("alert_q") or ""
    anomaly_q = request.GET.get("anomaly_q") or ""

    # --- CSV export still uses the filtered qs (but snapshot + dynamic) ---
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
            "dynamic_status",
        ])
        for o in qs.iterator():
            _attach_dynamic_status(o)
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
                o.dynamic_status or "",
            ])
        return resp

    # ----------------------
    # 2) SIDE TABLE 1: 10-min flagged (dynamic + flag_q)
    # ----------------------
    now = timezone.now()
    cutoff_10m = now - timedelta(minutes=10)

    recent_10m = (
        AccessPointObservation.objects
        .filter(server_ts__gte=cutoff_10m)
        .select_related("device")
        .order_by("-server_ts")
    )

    flag_q_lc = flag_q.lower()
    flagged_10min_list = []
    for o in recent_10m:
        _attach_dynamic_status(o)
        if not o.dynamic_flagged:
            continue
        if flag_q_lc:
            text = f"{o.ssid or ''} {o.bssid or ''}".lower()
            if flag_q_lc not in text:
                continue
        flagged_10min_list.append(o)

    flag_paginator = Paginator(flagged_10min_list, 10)
    flag_page_number = request.GET.get("flag_page")
    flag_page = flag_paginator.get_page(flag_page_number)

    # ----------------------
    # 3) SIDE TABLE 2: recent alerts (dynamic + alert_q)
    # ----------------------
    recent_obs = (
        AccessPointObservation.objects
        .select_related("device")
        .order_by("-server_ts")[:300]
    )

    alert_q_lc = alert_q.lower()
    alerts_list = []
    for o in recent_obs:
        _attach_dynamic_status(o)
        if not o.dynamic_flagged:
            continue
        if alert_q_lc:
            text = f"{o.ssid or ''} {o.bssid or ''}".lower()
            if alert_q_lc not in text:
                continue
        alerts_list.append(o)

    alerts_paginator = Paginator(alerts_list, 10)
    alert_page_number = request.GET.get("alert_page")
    alert_page = alerts_paginator.get_page(alert_page_number)

    # ----------------------
    # 4) WHITELIST ANOMALIES (dynamic_anomaly + anomaly_q)
    # ----------------------
    cutoff_60m = now - timedelta(minutes=60)
    recent_60m = (
        AccessPointObservation.objects
        .filter(server_ts__gte=cutoff_60m)
        .select_related("device")
        .order_by("-server_ts")
    )

    anomaly_q_lc = anomaly_q.lower()
    anomaly_rows = []
    for o in recent_60m:
        _attach_dynamic_status(o)
        if not o.dynamic_anomaly:
            continue
        if anomaly_q_lc:
            text = f"{o.ssid or ''} {o.bssid or ''}".lower()
            if anomaly_q_lc not in text:
                continue
        anomaly_rows.append(o)

    # ----------------------
    # 5) MAIN TABLE PAGINATION (attach dynamic status to visible rows)
    # ----------------------
    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get("page"))

    for o in page.object_list:
        _attach_dynamic_status(o)

    # keep other query params when changing *main* page
    keep = request.GET.copy()
    for key in ["page", "flag_page", "alert_page"]:
        if key in keep:
            del keep[key]
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

            # side tables + anomalies
            "flag_page": flag_page,
            "alert_page": alert_page,
            "anomaly_rows": anomaly_rows,

            # per-table search terms
            "flag_q": flag_q,
            "alert_q": alert_q,
            "anomaly_q": anomaly_q,
        },
    )


# ---------------------------------------------------------------------
# DYNAMIC UNWHITELISTED PAGE
# ---------------------------------------------------------------------
@login_required
def observations_unwhitelisted(request):
    """
    Dynamic version:
    - Recomputes whitelist status for each observation using _match_whitelist
    - Shows only observations that are currently NOT whitelisted
      (dynamic_flagged == True).
    """
    base_qs = (
        AccessPointObservation.objects
        .select_related("device")
        .order_by("-server_ts")
    )

    rows = []
    for o in base_qs:
        _attach_dynamic_status(o)
        if o.dynamic_flagged:
            rows.append(o)

    paginator = Paginator(rows, 25)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    return render(
        request,
        "ui/observations_unwhitelisted.html",
        {"page_obj": page_obj},
    )


# ---------------------------------------------------------------------
# DETAIL VIEW
# ---------------------------------------------------------------------
@login_required
def observation_detail(request, pk: int):
    o = get_object_or_404(
        AccessPointObservation.objects.select_related("device", "matched_group", "matched_entry"),
        pk=pk,
    )
    _attach_dynamic_status(o)
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


# ---------------------------------------------------------------------
# UNIQUE CURRENT UNREGISTERED APs
# ---------------------------------------------------------------------
@login_required
def unregistered_aps(request):
    """
    Unique UNREGISTERED_AP table:
    - Recomputes whitelist status dynamically using _match_whitelist
    - Keeps only observations whose *current* status is UNREGISTERED_AP
    - Deduplicates by (SSID, BSSID) and shows the latest row for each pair
    """

    # base queryset: newest first
    qs = (
        AccessPointObservation.objects
        .select_related("device")
        .order_by("-server_ts")
    )

    # optional simple search: ?q=some-text
    q = (request.GET.get("q") or "").strip().lower()

    latest_by_key = {}  # (ssid, bssid) -> obs

    for o in qs:
        _attach_dynamic_status(o)

        # only unregistered APs based on *current* whitelist
        if o.dynamic_status != "UNREGISTERED_AP":
            continue

        # small search filter
        if q:
            text = f"{o.ssid or ''} {o.bssid or ''}".lower()
            if q not in text:
                continue

        key = (o.ssid or "", o.bssid or "")
        # first time we see this key it's the newest, because qs is ordered -server_ts
        if key not in latest_by_key:
            latest_by_key[key] = o

    # collect & sort by time (most recent first)
    rows = sorted(
        latest_by_key.values(),
        key=lambda o: o.server_ts or timezone.now(),
        reverse=True,
    )

    paginator = Paginator(rows, 25)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    return render(
        request,
        "ui/unregistered_aps.html",
        {
            "page_obj": page_obj,
            "q": request.GET.get("q", ""),
            "total_unique": len(rows),
        },
    )

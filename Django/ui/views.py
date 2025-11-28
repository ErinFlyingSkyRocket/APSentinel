from datetime import timedelta, datetime
import csv
import json

from django.shortcuts import render, get_object_or_404
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.utils.dateparse import parse_date
from django.contrib.auth.decorators import login_required
from django.db.models import Q, Max, Count, Min, Avg
from django.db.models.functions import TruncMinute, TruncHour, TruncDate
from django.core.serializers.json import DjangoJSONEncoder
from django.utils import timezone

from devices.models import Device
from evidence.models import AccessPointObservation, WhitelistAnomalyOverride
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


def _is_anomaly_ignored(obs):
    """
    Check WhitelistAnomalyOverride to see if this dynamic anomaly
    should be suppressed (treated as 'acknowledged / intentional').

    Matching rules:
      - If BSSID is set in override: match by BSSID (case-insensitive).
      - Else if only SSID is set: match by SSID (case-insensitive).
      - If status is set in override: match that exact dynamic_status.
        If status is blank/NULL in override: match ANY status for that
        SSID/BSSID.
    """
    ssid = (obs.ssid or "").strip()
    bssid = (obs.bssid or "").strip()
    status = (getattr(obs, "dynamic_status", None) or "").strip()

    qs = WhitelistAnomalyOverride.objects.filter(active=True)

    # If we don't even have SSID/BSSID, nothing to match
    if bssid:
        qs = qs.filter(bssid__iexact=bssid)
    elif ssid:
        qs = qs.filter(ssid__iexact=ssid)
    else:
        return False

    if status:
        qs = qs.filter(Q(status__iexact=status) | Q(status="") | Q(status__isnull=True))

    return qs.exists()


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

    # total unique APs detected (by SSID/BSSID)
    total_unique_aps = (
        AccessPointObservation.objects
        .values("ssid", "bssid")
        .distinct()
        .count()
    )

    # dynamic current UNREGISTERED_APs (unique SSID/BSSID)
    base_qs = (
        AccessPointObservation.objects
        .select_related("device")
        .order_by("-server_ts")
    )
    latest_by_key = {}  # (ssid, bssid) -> seen
    for o in base_qs:
        _attach_dynamic_status(o)
        if o.dynamic_status != "UNREGISTERED_AP":
            continue
        key = (o.ssid or "", o.bssid or "")
        if key not in latest_by_key:
            latest_by_key[key] = True
    total_unregistered_aps = len(latest_by_key)

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
    # We group anomalies by (SSID, BSSID, dynamic_status) and stack counts.
    anomalies_qs = (
        AccessPointObservation.objects
        .select_related("device")
        .filter(server_ts__gte=cutoff_1h)
        .order_by("-server_ts")
    )

    cases_by_key = {}  # (ssid_norm, bssid_norm, status_norm) -> summary dict

    for o in anomalies_qs:
        _attach_dynamic_status(o)
        if not o.dynamic_anomaly:
            continue

        # Skip if user has created an override for this anomaly
        if _is_anomaly_ignored(o):
            continue

        ssid_norm = (o.ssid or "").strip()
        bssid_norm = (o.bssid or "").strip()
        status_norm = (getattr(o, "dynamic_status", None) or "").strip()

        key = (ssid_norm, bssid_norm, status_norm)
        existing = cases_by_key.get(key)

        if existing is None:
            cases_by_key[key] = {
                "ssid": o.ssid or "<hidden>",
                "bssid": o.bssid or "",
                "status": status_norm or "ANOMALY",
                "count": 1,
                "first_seen": o.server_ts,
                "last_seen": o.server_ts,
                # keep a sample observation to link to detail page if needed
                "sample": o,
            }
        else:
            existing["count"] += 1
            if o.server_ts:
                if existing["first_seen"] is None or o.server_ts < existing["first_seen"]:
                    existing["first_seen"] = o.server_ts
                if existing["last_seen"] is None or o.server_ts > existing["last_seen"]:
                    existing["last_seen"] = o.server_ts

    anomalies_critical = sorted(
        cases_by_key.values(),
        key=lambda c: c["last_seen"] or now,
        reverse=True,
    )

    return render(
        request,
        "ui/dashboard.html",
        {
            "total_obs": total_obs,
            "total_devices": total_devices,
            "total_unique_aps": total_unique_aps,
            "total_unregistered_aps": total_unregistered_aps,
            "active_device_count": active_count,
            "device_rows": device_rows,
            "current_unwhitelisted": current_unwhitelisted,
            "recent_alerts": recent_alerts,
            # NOTE: now a list of grouped anomaly "cases", not raw observations.
            # Each item has: ssid, bssid, status, count, first_seen, last_seen, sample
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
    - Whitelist anomalies table recomputes dynamic_anomaly each load and
      now shows *current* anomalies (latest row per SSID/BSSID), not just
      last 60 minutes.
    - Entries covered by a WhitelistAnomalyOverride are hidden from the
      anomaly table.
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
    # 4) WHITELIST ANOMALIES (CURRENT, dedup by SSID/BSSID + anomaly_q)
    # ----------------------
    # We scan all observations (newest first), keep only dynamic_anomaly==True,
    # skip any covered by WhitelistAnomalyOverride, and keep the latest row
    # per (ssid, bssid). This means anomalies remain listed until the whitelist
    # or overrides are edited so they are no longer anomalies.
    base_anom_qs = (
        AccessPointObservation.objects
        .select_related("device")
        .order_by("-server_ts")
    )

    anomaly_q_lc = anomaly_q.lower()
    latest_by_key = {}  # (ssid, bssid) -> obs

    for o in base_anom_qs:
        _attach_dynamic_status(o)
        if not o.dynamic_anomaly:
            continue

        # Respect overrides: if ignored, do not show
        if _is_anomaly_ignored(o):
            continue

        if anomaly_q_lc:
            text = f"{o.ssid or ''} {o.bssid or ''}".lower()
            if anomaly_q_lc not in text:
                continue

        key = (o.ssid or "", o.bssid or "")
        if key not in latest_by_key:
            latest_by_key[key] = o

    anomaly_rows = list(latest_by_key.values())
    anomaly_rows.sort(key=lambda x: x.server_ts or now, reverse=True)

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


@login_required
def ap_activity(request):
    """
    Time / anomaly analysis view:

    - Filter by device, SSID, BSSID, and time range (or lookback hours).
    - Show left-side table of *all* APs (whitelisted + non-whitelisted)
      seen in that window.
    - For a focused BSSID, show timeline + gaps + meta.
    - Show property drift (first vs last obs for that BSSID).
    - Show other APs using the same SSID in this window (possible evil twins).
    - Evil-twin frequency charts.
    - Timeline now supports 3 resolutions: per-minute, per-hour (24h per day),
      and per-day (calendar).
    """

    device_id = request.GET.get("device") or ""
    ssid = (request.GET.get("ssid") or "").strip()
    bssid = (request.GET.get("bssid") or "").strip()

    # default lookback hours if no explicit time range given
    try:
        hours_default = int(request.GET.get("hours", "12"))
    except ValueError:
        hours_default = 12

    now = timezone.now()

    since_str = request.GET.get("since") or ""
    until_str = request.GET.get("until") or ""

    # parse HTML datetime-local (YYYY-MM-DDTHH:MM) if given
    def parse_dt(val, fallback):
        if not val:
            return fallback
        try:
            naive = datetime.fromisoformat(val)
            return timezone.make_aware(naive, timezone.get_current_timezone())
        except Exception:
            return fallback

    since = parse_dt(since_str, now - timedelta(hours=hours_default))
    until = parse_dt(until_str, now)

    # ------------------------------------------------------------------
    # Base queryset: ALL observations in time window (no whitelist filter)
    # ------------------------------------------------------------------
    qs_window = (
        AccessPointObservation.objects
        .filter(
            server_ts__gte=since,
            server_ts__lte=until,
        )
        .select_related("device")
    )

    if device_id:
        qs_window = qs_window.filter(device_id=device_id)
    if ssid:
        qs_window = qs_window.filter(ssid__iexact=ssid)
    if bssid:
        qs_window = qs_window.filter(bssid__iexact=bssid)

    # ------------------------------------------------------------------
    # Left-side table: APs in selected window (all APs)
    # ------------------------------------------------------------------
    grouped = (
        qs_window.values("ssid", "bssid")
        .annotate(
            count=Count("id"),
            last_ts_max=Max("server_ts"),
        )
        .order_by("-count")[:200]
    )

    ap_list = []
    for row in grouped:
        g_ssid = row["ssid"]
        g_bssid = row["bssid"]

        # representative latest observation for this SSID+BSSID in window
        rep = (
            qs_window.filter(ssid=g_ssid, bssid=g_bssid)
            .order_by("-server_ts")
            .first()
        )

        channel = ""
        security = ""
        device_name = ""
        dynamic_status = None
        dynamic_anomaly = False

        if rep:
            _attach_dynamic_status(rep)
            dynamic_status = getattr(rep, "dynamic_status", None)
            dynamic_anomaly = getattr(rep, "dynamic_anomaly", False)
            channel = getattr(rep, "channel", "")
            security = getattr(rep, "security", "") or ""
            device_name = rep.device.name if rep.device else ""

        ap_list.append(
            {
                "ssid": g_ssid or "<hidden>",
                "bssid": g_bssid or "",
                "count": row["count"],
                "last_ts_max": row["last_ts_max"],
                "channel": channel,
                "security": security,
                "device_name": device_name,
                "dynamic_status": dynamic_status,
                "dynamic_anomaly": dynamic_anomaly,
            }
        )

    # ------------------------------------------------------------------
    # Pick one AP for the timeline chart + details
    # ------------------------------------------------------------------
    current_bssid = bssid
    if not current_bssid and ap_list:
        current_bssid = ap_list[0]["bssid"]

    # minute-level
    chart_labels = []
    chart_counts = []
    chart_rssi = []
    # day-level
    chart_day_labels = []
    chart_day_counts = []
    chart_day_rssi = []

    # NEW: 24h-per-day structure for hour view
    hour_series_by_day_out = {}  # day_str -> {hour_labels, counts, avg_rssi}
    hour_day_labels = []

    gaps = []
    current_ssid = ""
    current_device_name = ""
    ap_stats = None
    device_count = 0
    current_meta = {}
    property_drift = []
    ssid_siblings = []
    gap_threshold = timedelta(minutes=30)

    # evil-twin per-day and per-hour structures
    evil_day_labels = []
    evil_day_counts = []
    evil_series_by_day_out = {}

    if current_bssid:
        ap_qs = qs_window.filter(bssid=current_bssid).order_by("server_ts")

        first_obs = ap_qs.first()
        last_obs = ap_qs.last()

        if first_obs:
            current_ssid = first_obs.ssid or "<hidden>"
            current_device_name = first_obs.device.name if first_obs.device else "—"

        # ------------------------------------------------------------------
        # 1) Per-minute buckets: count + avg RSSI
        # ------------------------------------------------------------------
        minute_bucketed = (
            ap_qs.annotate(bucket_min=TruncMinute("server_ts"))
            .values("bucket_min")
            .annotate(
                count=Count("id"),
                avg_rssi=Avg("rssi_current"),
            )
            .order_by("bucket_min")
        )

        chart_labels = [row["bucket_min"].isoformat() for row in minute_bucketed]
        chart_counts = [row["count"] for row in minute_bucketed]
        chart_rssi = [
            row["avg_rssi"] if row["avg_rssi"] is not None else None
            for row in minute_bucketed
        ]

        # ------------------------------------------------------------------
        # 2) Per-day buckets (calendar-style view)
        # ------------------------------------------------------------------
        day_bucketed = (
            ap_qs.annotate(bucket_day=TruncDate("server_ts"))
            .values("bucket_day")
            .annotate(
                count=Count("id"),
                avg_rssi=Avg("rssi_current"),
            )
            .order_by("bucket_day")
        )

        chart_day_labels = [
            row["bucket_day"].isoformat() if row["bucket_day"] else ""
            for row in day_bucketed
        ]
        chart_day_counts = [row["count"] for row in day_bucketed]
        chart_day_rssi = [
            row["avg_rssi"] if row["avg_rssi"] is not None else None
            for row in day_bucketed
        ]

        # ------------------------------------------------------------------
        # 3) NEW: 24-hour structure per calendar day for hour view
        #     hours_raw[YYYY-MM-DD][hour] = {count, rssi_sum, rssi_n}
        # ------------------------------------------------------------------
        hours_raw = {}
        for ts, rssi in ap_qs.values_list("server_ts", "rssi_current"):
            if not ts:
                continue
            ts_local = timezone.localtime(ts)
            d_str = ts_local.date().isoformat()
            h = ts_local.hour  # 0..23

            d_map = hours_raw.setdefault(d_str, {})
            slot = d_map.setdefault(h, {"count": 0, "rssi_sum": 0.0, "rssi_n": 0})
            slot["count"] += 1
            if rssi is not None:
                try:
                    slot["rssi_sum"] += float(rssi)
                    slot["rssi_n"] += 1
                except (TypeError, ValueError):
                    pass

        for d_str, hours in hours_raw.items():
            labels = list(range(24))
            counts = []
            avg_rssi = []
            for h in labels:
                slot = hours.get(h)
                if slot:
                    counts.append(slot["count"])
                    if slot["rssi_n"]:
                        avg_rssi.append(slot["rssi_sum"] / slot["rssi_n"])
                    else:
                        avg_rssi.append(None)
                else:
                    counts.append(0)
                    avg_rssi.append(None)

            hour_series_by_day_out[d_str] = {
                "hour_labels": labels,
                "counts": counts,
                "avg_rssi": avg_rssi,
            }

        hour_day_labels = sorted(hour_series_by_day_out.keys())

        # ------------------------------------------------------------------
        # Gap detection (> 30 minutes between detections)
        # ------------------------------------------------------------------
        timestamps = list(ap_qs.values_list("server_ts", flat=True))
        prev_ts = None
        for ts in timestamps:
            if prev_ts is not None:
                delta = ts - prev_ts
                if delta > gap_threshold:
                    gaps.append(
                        {
                            "start": prev_ts,
                            "end": ts,
                            "minutes": int(delta.total_seconds() // 60),
                        }
                    )
            prev_ts = ts

        # aggregate stats for this AP
        ap_stats = ap_qs.aggregate(
            first_seen=Min("server_ts"),
            last_seen=Max("server_ts"),
            count=Count("id"),
            min_rssi=Min("rssi_current"),
            max_rssi=Max("rssi_current"),
            avg_rssi=Avg("rssi_current"),
        )
        device_count = ap_qs.values("device_id").distinct().count()

        # ---------------------------------------------
        # Evil-twin anomalies per day / per hour
        # ---------------------------------------------
        evil_series_by_day = {}  # day_str -> {hour -> {"count", "rssi_sum", "rssi_n"}}

        for obs in ap_qs:
            _attach_dynamic_status(obs)
            if not getattr(obs, "dynamic_anomaly", False):
                continue

            ts = getattr(obs, "server_ts", None)
            if not ts:
                continue

            ts_local = timezone.localtime(ts)
            day_str = ts_local.date().isoformat()
            hour = ts_local.hour  # 0..23

            day_bucket = evil_series_by_day.setdefault(day_str, {})
            hour_bucket = day_bucket.setdefault(
                hour,
                {"count": 0, "rssi_sum": 0.0, "rssi_n": 0},
            )

            hour_bucket["count"] += 1

            rssi = getattr(obs, "rssi_current", None)
            if rssi is not None:
                try:
                    hour_bucket["rssi_sum"] += float(rssi)
                    hour_bucket["rssi_n"] += 1
                except (TypeError, ValueError):
                    pass

        for day_str, hours in evil_series_by_day.items():
            hour_labels = list(range(24))
            counts = []
            avg_rssi = []
            total_for_day = 0

            for h in hour_labels:
                hb = hours.get(h, {"count": 0, "rssi_sum": 0.0, "rssi_n": 0})
                c = hb["count"]
                total_for_day += c
                counts.append(c)
                if hb["rssi_n"]:
                    avg_rssi.append(round(hb["rssi_sum"] / hb["rssi_n"], 1))
                else:
                    avg_rssi.append(None)

            evil_series_by_day_out[day_str] = {
                "hour_labels": hour_labels,
                "counts": counts,
                "avg_rssi": avg_rssi,
                "total": total_for_day,
            }

        evil_day_labels = sorted(evil_series_by_day_out.keys())
        evil_day_counts = [
            evil_series_by_day_out[d]["total"] for d in evil_day_labels
        ]

        # ---------------------------------------------
        # Meta + dynamic status for focused AP (last)
        # ---------------------------------------------
        ref = last_obs or first_obs
        if ref:
            _attach_dynamic_status(ref)

            ref_ssid = ref.ssid or ""
            ref_channel = getattr(ref, "channel", None)
            ref_security = getattr(ref, "security", "") or ""
            ref_oui = getattr(ref, "oui", "") or ""
            ref_rsn_group = getattr(ref, "rsn_group", "") or ""
            ref_rsn_pair = getattr(ref, "rsn_pair", "") or ""
            ref_akm = getattr(ref, "akm", "") or ""
            ref_pmf = getattr(ref, "pmf", "") or ""

            current_meta = {
                "ssid": ref.ssid or "<hidden>",
                "bssid": ref.bssid or "",
                "oui": ref_oui,
                "channel": ref_channel,
                "security": ref_security,
                "rsn_group": ref_rsn_group,
                "rsn_pair": ref_rsn_pair,
                "akm": ref_akm,
                "pmf": ref_pmf,
                "dynamic_status": getattr(ref, "dynamic_status", None),
                "dynamic_anomaly": getattr(ref, "dynamic_anomaly", False),
            }

            # ---------------------------------------------
            # Property drift (first vs last for this BSSID)
            # ---------------------------------------------
            def fmt(v):
                return v if v not in (None, "") else "—"

            def add_diff(label, old, new):
                if old != new:
                    property_drift.append(
                        {"label": label, "old": fmt(old), "new": fmt(new)}
                    )

            if first_obs and last_obs and first_obs.id != last_obs.id:
                add_diff("Channel", getattr(first_obs, "channel", None), ref_channel)
                add_diff("Security", getattr(first_obs, "security", ""), ref_security)
                add_diff("OUI", getattr(first_obs, "oui", ""), ref_oui)
                add_diff("RSN group", getattr(first_obs, "rsn_group", ""), ref_rsn_group)
                add_diff("RSN pair", getattr(first_obs, "rsn_pair", ""), ref_rsn_pair)
                add_diff("AKM", getattr(first_obs, "akm", ""), ref_akm)
                add_diff("PMF", getattr(first_obs, "pmf", ""), ref_pmf)

            # ----------------------------------------------------------
            # Other BSSIDs using the *same SSID* in this window
            # (evil-twin style view)
            # ----------------------------------------------------------
            if ref_ssid:
                siblings_base = (
                    qs_window
                    .filter(ssid=ref_ssid)
                    .exclude(bssid=current_bssid)
                )

                siblings_grouped = (
                    siblings_base.values("bssid")
                    .annotate(
                        count=Count("id"),
                        last_seen=Max("server_ts"),
                    )
                    .order_by("-last_seen")
                )

                for row in siblings_grouped:
                    sib_bssid = row["bssid"]
                    rep = (
                        siblings_base
                        .filter(bssid=sib_bssid)
                        .order_by("-server_ts")
                        .first()
                    )
                    if not rep:
                        continue

                    _attach_dynamic_status(rep)

                    ssid_siblings.append(
                        {
                            "bssid": sib_bssid or "",
                            "count": row["count"],
                            "last_seen": row["last_seen"],
                            "channel": getattr(rep, "channel", None),
                            "security": getattr(rep, "security", "") or "",
                            "rsn_group": getattr(rep, "rsn_group", "") or "",
                            "rsn_pair": getattr(rep, "rsn_pair", "") or "",
                            "akm": getattr(rep, "akm", "") or "",
                            "pmf": getattr(rep, "pmf", "") or "",
                            "dynamic_status": getattr(rep, "dynamic_status", None),
                            "dynamic_anomaly": getattr(rep, "dynamic_anomaly", False),
                        }
                    )

    devices = Device.objects.all().order_by("name")

    context = {
        "devices": devices,
        "device_id": device_id,
        "ssid": ssid,
        "bssid": bssid,
        "since": since,
        "until": until,
        "hours_default": hours_default,
        "ap_list": ap_list,
        "current_bssid": current_bssid,
        "current_ssid": current_ssid,
        "current_device_name": current_device_name,

        # minute resolution
        "chart_labels_json": json.dumps(chart_labels, cls=DjangoJSONEncoder),
        "chart_values_json": json.dumps(chart_counts, cls=DjangoJSONEncoder),
        "chart_rssi_json": json.dumps(chart_rssi, cls=DjangoJSONEncoder),

        # day resolution
        "chart_day_labels_json": json.dumps(chart_day_labels, cls=DjangoJSONEncoder),
        "chart_day_counts_json": json.dumps(chart_day_counts, cls=DjangoJSONEncoder),
        "chart_day_rssi_json": json.dumps(chart_day_rssi, cls=DjangoJSONEncoder),

        # NEW: 24h-per-day hour resolution
        "hour_series_by_day_json": json.dumps(hour_series_by_day_out, cls=DjangoJSONEncoder),
        "hour_day_labels_json": json.dumps(hour_day_labels, cls=DjangoJSONEncoder),

        "gaps": gaps,
        "gap_threshold_minutes": int(gap_threshold.total_seconds() // 60),
        "ap_stats": ap_stats,
        "device_count": device_count,
        "current_meta": current_meta,
        "property_drift": property_drift,
        "ssid_siblings": ssid_siblings,

        # evil-twin charts
        "evil_day_labels_json": json.dumps(evil_day_labels, cls=DjangoJSONEncoder),
        "evil_day_counts_json": json.dumps(evil_day_counts, cls=DjangoJSONEncoder),
        "evil_series_by_day_json": json.dumps(evil_series_by_day_out, cls=DjangoJSONEncoder),
    }

    return render(request, "ui/ap_activity.html", context)

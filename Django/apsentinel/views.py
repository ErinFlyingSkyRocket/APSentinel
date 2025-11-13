# apsentinel/views.py
import json
import logging
from datetime import datetime
from typing import Optional
from base64 import b64encode

from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from django.utils import timezone as dj_timezone
from django.shortcuts import render

from devices.models import Device
from evidence.models import (
    AccessPointObservation,
    AccessPointWhitelistGroup,
    AccessPointWhitelistEntry,
)

from . import hashchain

# try to use your helper if it exists
try:
    from .crypto_utils import verify_ecdsa_p256_sha256
except Exception:  # fallback if not present
    verify_ecdsa_p256_sha256 = None

logger = logging.getLogger("apsentinel")


def health(request):
    return JsonResponse({"status": "ok"})


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
def _parse_iso_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            return dj_timezone.make_aware(dt, dj_timezone.utc)
        return dt.astimezone(dj_timezone.utc)
    except Exception:
        return None


def _match_whitelist(ssid: str, bssid: str, security: str, channel: int, oui: str):
    """
    Whitelist precedence:
      1) exact BSSID in active group
      2) same SSID + security in that group (any BSSID)
      3) same SSID in non-strict group
      4) else -> unregistered / rejected
    """
    if not ssid:
        return None, None, "UNREGISTERED_AP"

    groups = AccessPointWhitelistGroup.objects.filter(ssid=ssid, is_active=True)
    if not groups.exists():
        return None, None, "UNREGISTERED_AP"

    for group in groups:
        # 1) exact BSSID
        entry = group.entries.filter(bssid=bssid, is_active=True).first()
        if entry:
            if entry.channel and channel and int(entry.channel) != int(channel):
                return group, entry, "CHANNEL_MISMATCH"
            if entry.security and security and entry.security != security:
                return group, entry, "SECURITY_MISMATCH"
            return group, entry, "WHITELISTED_STRONG"

        # 2) any-BSSID but same security
        if security:
            entry = group.entries.filter(
                bssid__isnull=True,
                is_active=True,
                security=security,
            ).first()
            if entry:
                return group, entry, "WHITELISTED_WEAK"

        # 3) non-strict group -> SSID ok, but AP not explicitly listed
        if not group.strict:
            return group, None, "KNOWN_SSID_BUT_UNEXPECTED_AP"

    # 4) we have groups but none matched cleanly
    return groups.first(), None, "KNOWN_SSID_REJECTED"


def _xy_to_uncompressed_pubkey(x_hex: str, y_hex: str) -> bytes:
    """
    ESP32 sends X and Y as hex (big-endian). ECDSA P-256 uncompressed key is:
    0x04 || X(32 bytes) || Y(32 bytes)
    """
    x = bytes.fromhex(x_hex)
    y = bytes.fromhex(y_hex)
    if len(x) != 32 or len(y) != 32:
        raise ValueError("x/y must be 32 bytes for P-256")
    return b"\x04" + x + y


def _build_pem_from_xy(x_hex: str, y_hex: str) -> str:
    """
    Build a SubjectPublicKeyInfo DER → PEM for P-256 from x/y.
    """
    # ASN.1 header for: ecPublicKey, prime256v1
    spki_prefix = bytes.fromhex(
        # SEQ
        "3059"
        # SEQ
        "3013"
        # OID ecPublicKey 1.2.840.10045.2.1
        "0607" "2A8648CE3D0201"
        # OID prime256v1 1.2.840.10045.3.1.7
        "0608" "2A8648CE3D030107"
        # BIT STRING
        "0342" "00"
    )
    pubkey = _xy_to_uncompressed_pubkey(x_hex, y_hex)
    der = spki_prefix + pubkey
    b64 = b64encode(der).decode("ascii")
    lines = ["-----BEGIN PUBLIC KEY-----"]
    for i in range(0, len(b64), 64):
        lines.append(b64[i : i + 64])
    lines.append("-----END PUBLIC KEY-----")
    return "\n".join(lines)


def _verify_obs_signature(
    pem: str,
    canonical: str,
    sig_block: dict,
    hash_hex: Optional[str] = None,
) -> bool:
    """
    Verify one observation.

    ESP sends:
      sig: {
        "alg": "ECDSA_P256_SHA256",
        "over": "SHA256(canonical)",
        "r": "...",
        "s": "..."
      }
    """
    if not pem or not canonical or not sig_block:
        return False
    if sig_block.get("alg") not in ("ECDSA_P256_SHA256", "ECDSA_P-256_SHA256"):
        return False

    r_hex = sig_block.get("r")
    s_hex = sig_block.get("s")
    if not r_hex or not s_hex:
        return False

    over = sig_block.get("over")

    # 1) try user helper if present
    if verify_ecdsa_p256_sha256 is not None:
        try:
            if over == "SHA256(canonical)":
                if not hash_hex:
                    return False
                msg = bytes.fromhex(hash_hex)
                return verify_ecdsa_p256_sha256(
                    pem_public_key=pem,
                    message=msg,
                    r_hex=r_hex,
                    s_hex=s_hex,
                )
            else:  # legacy path
                return verify_ecdsa_p256_sha256(
                    pem_public_key=pem,
                    message=canonical.encode("utf-8"),
                    r_hex=r_hex,
                    s_hex=s_hex,
                )
        except Exception:
            return False

    # 2) fallback: cryptography
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        public_key = serialization.load_pem_public_key(pem.encode("utf-8"))
        r_int = int(r_hex, 16)
        s_int = int(s_hex, 16)
        der_sig = encode_dss_signature(r_int, s_int)

        if over == "SHA256(canonical)":
            if not hash_hex:
                return False
            public_key.verify(
                der_sig,
                bytes.fromhex(hash_hex),
                ec.ECDSA(hashes.SHA256()),
            )
        else:
            public_key.verify(
                der_sig,
                canonical.encode("utf-8"),
                ec.ECDSA(hashes.SHA256()),
            )
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------
# Ingest endpoint (secure ESP32 -> Django)
# ---------------------------------------------------------------------
@csrf_exempt
def ingest_observation(request):
    """
    Strict-ish ingest: ESP32 posts observations signed per-record.
    Now also builds a per-device hash chain for chain-of-custody.
    """
    if request.method != "POST":
        return HttpResponseBadRequest("POST required")

    # 1) parse JSON
    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    device_block = data.get("device") or {}
    device_mac = device_block.get("mac")
    device_name = device_block.get("name") or device_mac
    if not device_mac:
        return HttpResponseBadRequest("Device MAC required")

    # 2) device
    device, _ = Device.objects.get_or_create(
        name=device_name,
        defaults={"is_active": True},
    )
    if not device.is_active:
        return HttpResponseForbidden("Device not allowed")

    # 3) ensure pubkey
    device_pub_pem = getattr(device, "pubkey_pem", None)
    if not device_pub_pem:
        pubkey_block = device_block.get("pubkey") or {}
        x_hex = pubkey_block.get("x")
        y_hex = pubkey_block.get("y")
        if not x_hex or not y_hex:
            return HttpResponseForbidden("Device public key required")
        try:
            device_pub_pem = _build_pem_from_xy(x_hex, y_hex)
        except Exception as e:
            logger.warning("Failed to build PEM from XY for %s: %s", device_mac, e)
            return HttpResponseForbidden("Bad public key")
        device.pubkey_pem = device_pub_pem

    device.last_seen = dj_timezone.now()
    device.save()

    # 4) observations list
    #    New firmware may send under "aps"; keep old "observations" for compatibility.
    obs_list = data.get("observations") or data.get("aps") or []
    if not isinstance(obs_list, list):
        return HttpResponseBadRequest("'observations' or 'aps' must be a list")

    now = dj_timezone.now()
    stored_ids = []
    rejected = 0

    # 5) process
    with transaction.atomic():
        for o in obs_list:
            canonical = o.get("canonical")
            sig_block = o.get("sig") or {}
            hash_hex = o.get("hash_sha256")

            # verify signature
            if not _verify_obs_signature(
                device_pub_pem,
                canonical,
                sig_block,
                hash_hex,
            ):
                rejected += 1
                continue

            # map fields
            ssid = o.get("ssid") or ""
            bssid = o.get("bssid") or ""
            oui = o.get("oui") or ""
            raw_ch = o.get("ch") or o.get("channel") or 1
            try:
                channel = int(raw_ch)
            except (TypeError, ValueError):
                channel = 1

            security = o.get("security")
            rsn_text = o.get("rsn")
            akm_list = o.get("akm")
            pmf_block = o.get("pmf") or {}

            rssi_cur = o.get("rssi_cur")
            rssi_best = o.get("rssi_best")
            beacons = o.get("beacons")
            last_seen_ms = o.get("last_seen_ms")

            # whitelist decision
            matched_group, matched_entry, status = _match_whitelist(
                ssid=ssid,
                bssid=bssid,
                security=security,
                channel=channel,
                oui=oui,
            )

            # 🔐 HASH CHAIN PART
            canonical_bytes = (canonical or "").encode("utf-8")
            payload_hash = hashchain.compute_payload_hash(canonical_bytes)

            # make previous lookup deterministic
            last_obs = (
                AccessPointObservation.objects
                .filter(device=device)
                .order_by("-server_ts", "-id")
                .first()
            )

            # GENESIS: first record for this device uses 32x00 as prev hash
            genesis = b"\x00" * 32
            prev_chain_hash = last_obs.chain_hash if last_obs else genesis

            server_ts_iso = now.isoformat()
            chain_hash = hashchain.compute_chain_hash(
                prev_chain_hash=prev_chain_hash,
                payload_hash=payload_hash,
                server_ts_iso=server_ts_iso,
            )

            # create row
            obj = AccessPointObservation.objects.create(
                device=device,
                ssid=ssid,
                bssid=bssid,
                oui=oui,
                channel=channel,
                rssi_current=rssi_cur,
                rssi_best=rssi_best,
                beacons=beacons,
                sensor_last_seen_ms=last_seen_ms,
                security=security,
                rsn_text=rsn_text,
                akm_list=akm_list,
                pmf_capable=bool(pmf_block.get("cap")),
                pmf_required=bool(pmf_block.get("req")),
                canonical=canonical,
                hash_sha256=hash_hex,
                sig_alg=sig_block.get("alg"),
                sig_r=sig_block.get("r"),
                sig_s=sig_block.get("s"),
                server_ts=now,
                matched_group=matched_group,
                matched_entry=matched_entry,
                match_status=status,
                # 🚨 alert when not strongly/weakly whitelisted
                is_flagged=status not in ("WHITELISTED_STRONG", "WHITELISTED_WEAK"),
                prev_chain_hash=prev_chain_hash,
                chain_hash=chain_hash,
                integrity_ok=True,
            )
            stored_ids.append(obj.id)

    logger.info(
        "Ingest from %s: stored=%d rejected_sig=%d",
        device_mac,
        len(stored_ids),
        rejected,
    )

    return JsonResponse(
        {
            "status": "ok",
            "stored": len(stored_ids),
            "rejected": rejected,
            "ids": stored_ids,
        }
    )


# ---------------------------------------------------------------------
# Hash chain analysis UI
# ---------------------------------------------------------------------
def hashchain_analysis(request):
    """
    UI page to view & verify the hash chain for ONE device (ESP32).
    Supports filters:
      - ?ssid=Hospital
      - ?bssid=AA:BB:...
      - ?integrity=bad|ok|all
      - ?since=2025-01-01
      - ?until=2025-01-31
      - ?limit=200
    """
    devices = Device.objects.filter(is_active=True).order_by("name")
    device_id = request.GET.get("device")

    # no device chosen -> empty page
    if not device_id:
        return render(
            request,
            "apsentinel/hashchain_analysis.html",
            {
                "devices": devices,
                "selected_device": None,
                "rows": [],
                "chart_timeline": "[]",
                "chart_bssid": "[]",
                "totals": {"total": 0, "ok": 0, "bad": 0},
                "filter_ssid": "",
                "filter_bssid": "",
                "filter_integrity": "all",
                "filter_since": "",
                "filter_until": "",
                "filter_limit": "",
            },
        )

    try:
        device = Device.objects.get(id=device_id)
    except Device.DoesNotExist:
        return render(
            request,
            "apsentinel/hashchain_analysis.html",
            {
                "devices": devices,
                "selected_device": None,
                "rows": [],
                "chart_timeline": "[]",
                "chart_bssid": "[]",
                "totals": {"total": 0, "ok": 0, "bad": 0},
                "error": "Device not found",
            },
        )

    # query all obs for this device, ordered
    obs_qs = (
        AccessPointObservation.objects
        .filter(device=device)
        .order_by("server_ts", "id")
    )

    # build full chain first
    full_rows, full_timeline, full_totals = _build_chain_rows_from_queryset(obs_qs)

    # ------------------------------------------------------------------
    # apply UI filters on top of built rows
    # ------------------------------------------------------------------
    f_ssid = (request.GET.get("ssid") or "").strip()
    f_bssid = (request.GET.get("bssid") or "").strip().upper()
    f_integrity = request.GET.get("integrity") or "all"
    f_since = (request.GET.get("since") or "").strip()
    f_until = (request.GET.get("until") or "").strip()
    f_limit = request.GET.get("limit") or ""

    filtered_rows = []
    for r in full_rows:
        o = r["obs"]

        # date filters
        if f_since:
            try:
                since_dt = datetime.fromisoformat(f_since)
                since_dt = dj_timezone.make_aware(since_dt)
                if o.server_ts < since_dt:
                    continue
            except Exception:
                pass
        if f_until:
            try:
                until_dt = datetime.fromisoformat(f_until)
                until_dt = dj_timezone.make_aware(until_dt)
                if o.server_ts > until_dt:
                    continue
            except Exception:
                pass

        # ssid filter (contains, case-insensitive)
        if f_ssid:
            if not o.ssid or f_ssid.lower() not in o.ssid.lower():
                continue

        # bssid filter (exact-ish, upper)
        if f_bssid:
            if not o.bssid or o.bssid.upper() != f_bssid:
                continue

        # integrity filter
        if f_integrity == "ok" and not r["ok"]:
            continue
        if f_integrity == "bad" and r["ok"]:
            continue

        filtered_rows.append(r)

    # limit
    if f_limit:
        try:
            lim = int(f_limit)
            filtered_rows = filtered_rows[: max(lim, 1)]
        except ValueError:
            pass

    # rebuild charts from filtered rows
    timeline_points = [
        {"ts": r["obs"].server_ts.isoformat(), "ok": r["ok"], "id": r["obs"].id}
        for r in filtered_rows
    ]

    bssid_counts = {}
    for r in filtered_rows:
        o = r["obs"]
        if o.bssid:
            bssid_counts[o.bssid] = bssid_counts.get(o.bssid, 0) + 1
    top_bssid_items = sorted(bssid_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    chart_bssid = json.dumps(
        [{"bssid": b, "count": c} for (b, c) in top_bssid_items]
    )

    totals = {
        "total": len(filtered_rows),
        "ok": sum(1 for r in filtered_rows if r["ok"]),
        "bad": sum(1 for r in filtered_rows if not r["ok"]),
    }

    return render(
        request,
        "apsentinel/hashchain_analysis.html",
        {
            "devices": devices,
            "selected_device": device,
            "rows": filtered_rows,
            "chart_timeline": json.dumps(timeline_points),
            "chart_bssid": chart_bssid,
            "totals": totals,
            "filter_ssid": f_ssid,
            "filter_bssid": f_bssid,
            "filter_integrity": f_integrity,
            "filter_since": f_since,
            "filter_until": f_until,
            "filter_limit": f_limit,
        },
    )


def _build_chain_rows_from_queryset(obs_qs):
    """
    Helper to replay the chain over an ordered queryset of observations.
    Returns (rows, timeline_points, totals)
    """
    rows = []
    timeline_points = []
    expected_prev = b"\x00" * 32  # GENESIS seed
    total_ok = 0
    total_bad = 0

    for obs in obs_qs:
        canonical_bytes = (obs.canonical or "").encode("utf-8")
        payload_hash = hashchain.compute_payload_hash(canonical_bytes)
        server_ts_iso = obs.server_ts.isoformat()

        expected_chain = hashchain.compute_chain_hash(
            prev_chain_hash=expected_prev,
            payload_hash=payload_hash,
            server_ts_iso=server_ts_iso,
        )

        stored_prev = obs.prev_chain_hash or b""
        stored_chain = obs.chain_hash or b""

        ok = (stored_prev == expected_prev) and (stored_chain == expected_chain)

        rows.append(
            {
                "obs": obs,
                "expected_prev": expected_prev.hex(),
                "stored_prev": stored_prev.hex() if stored_prev else "",
                "expected_chain": expected_chain.hex(),
                "stored_chain": stored_chain.hex() if stored_chain else "",
                "ok": ok,
            }
        )

        timeline_points.append(
            {
                "ts": obs.server_ts.isoformat(),
                "ok": ok,
                "id": obs.id,
            }
        )

        if ok:
            total_ok += 1
        else:
            total_bad += 1

        # advance chain
        expected_prev = expected_chain

    totals = {
        "total": len(rows),
        "ok": total_ok,
        "bad": total_bad,
    }
    return rows, timeline_points, totals

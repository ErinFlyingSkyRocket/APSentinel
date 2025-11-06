# apsentinel/views.py
import json
import logging
from datetime import datetime
from typing import Optional

from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from django.utils import timezone as dj_timezone

from devices.models import Device
from evidence.models import (
    AccessPointObservation,
    AccessPointWhitelistGroup,
    AccessPointWhitelistEntry,
)

# if you already have this helper, we'll use it
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
    Precedence:
      1) exact BSSID in active group
      2) same SSID + security in that group (any BSSID)
      3) same SSID in non-strict group
      4) else -> unregistered / rejected
    with extra channel/security mismatch states.
    """
    if not ssid:
        return None, None, "UNREGISTERED_AP"

    groups = AccessPointWhitelistGroup.objects.filter(ssid=ssid, is_active=True)
    if not groups.exists():
        return None, None, "UNREGISTERED_AP"

    for group in groups:
        # exact BSSID
        entry = group.entries.filter(bssid=bssid, is_active=True).first()
        if entry:
            if entry.channel and channel and int(entry.channel) != int(channel):
                return group, entry, "CHANNEL_MISMATCH"
            if entry.security and security and entry.security != security:
                return group, entry, "SECURITY_MISMATCH"
            return group, entry, "WHITELISTED_STRONG"

        # any-BSSID but same security
        if security:
            entry = group.entries.filter(
                bssid__isnull=True,
                is_active=True,
                security=security,
            ).first()
            if entry:
                return group, entry, "WHITELISTED_WEAK"

        # non-strict group -> SSID ok, but we didn't list this AP
        if not group.strict:
            return group, None, "KNOWN_SSID_BUT_UNEXPECTED_AP"

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

    This is the standard:
    SEQUENCE(
      SEQUENCE(1.2.840.10045.2.1, 1.2.840.10045.3.1.7),
      BIT STRING(<uncompressed point>)
    )

    To keep it simple here, we emit the OpenSSL-style header and base64 ourselves.
    """
    from base64 import b64encode

    # ASN.1 header for: ecPublicKey, prime256v1
    # This is a fixed byte sequence for P-256 public keys.
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
    # split into 64-char lines
    for i in range(0, len(b64), 64):
        lines.append(b64[i : i + 64])
    lines.append("-----END PUBLIC KEY-----")
    return "\n".join(lines)


def _verify_obs_signature(pem: str, canonical: str, sig_block: dict) -> bool:
    """
    Verify one observation:
      - canonical: string the ESP32 signed
      - sig_block: {"alg": "...", "r": "HEX", "s": "HEX"}
    We recompute SHA-256(canonical) and verify ECDSA P-256 with (r,s).
    We delegate to your existing crypto_utils if available.
    """
    if not canonical or not sig_block:
        return False
    if sig_block.get("alg") not in ("ECDSA_P256_SHA256", "ECDSA_P-256_SHA256"):
        return False

    r_hex = sig_block.get("r")
    s_hex = sig_block.get("s")
    if not r_hex or not s_hex:
        return False

    # your helper probably expects a base64 DER sig or raw r/s — we don't know.
    # simplest: pass raw hex r/s + canonical and let your helper deal with it.
    if verify_ecdsa_p256_sha256 is None:
        # if no helper, accept nothing
        return False

    try:
        ok = verify_ecdsa_p256_sha256(
            pem_public_key=pem,
            message=canonical.encode("utf-8"),
            r_hex=r_hex,
            s_hex=s_hex,
        )
    except TypeError:
        # in case your helper has a slightly different signature
        ok = False

    return ok


# ---------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------
@csrf_exempt
def ingest_observation(request):
    """
    Strict-ish ingest: uses the ESP32's per-record ECDSA P-256 signatures.
    Flow:
      - POST JSON with "device" and "observations"
      - device contains mac and pubkey (x,y) on first run
      - we store that PEM on the Device model (if the model has a field)
      - for each observation:
          * verify signature against stored PEM
          * if ok -> save + whitelist evaluation
          * if not ok -> skip
    """
    if request.method != "POST":
        return HttpResponseBadRequest("POST required")

    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    device_block = data.get("device") or {}
    device_mac = device_block.get("mac")
    if not device_mac:
        return HttpResponseBadRequest("Device MAC required")

    # get or create device
    device, _ = Device.objects.get_or_create(
        mac=device_mac,
        defaults={"name": device_mac, "is_active": True},
    )

    # ensure device has a public key PEM
    device_pub_pem = getattr(device, "pubkey_pem", None)
    if not device_pub_pem:
        # try to build from x/y in current payload
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

        # save on device if field exists
        if hasattr(device, "pubkey_pem"):
            device.pubkey_pem = device_pub_pem

    # update device heartbeat
    device.last_seen = dj_timezone.now()
    device.is_active = True
    # save all updated fields
    try:
        device.save()
    except Exception:
        # if model has no pubkey_pem field, saving may still succeed
        device.save()

    obs_list = data.get("observations") or []
    if not isinstance(obs_list, list):
        return HttpResponseBadRequest("'observations' must be a list")

    now = dj_timezone.now()
    stored_ids = []
    rejected = 0

    with transaction.atomic():
        for o in obs_list:
            canonical = o.get("canonical")
            sig_block = o.get("sig") or {}

            # verify signature for this record
            if not _verify_obs_signature(device_pub_pem, canonical, sig_block):
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

            hash_sha256 = o.get("hash_sha256")

            # whitelist decision
            matched_group, matched_entry, status = _match_whitelist(
                ssid=ssid,
                bssid=bssid,
                security=security,
                channel=channel,
                oui=oui,
            )

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
                hash_sha256=hash_sha256,
                sig_alg=sig_block.get("alg"),
                sig_r=sig_block.get("r"),
                sig_s=sig_block.get("s"),
                server_ts=now,
                matched_group=matched_group,
                matched_entry=matched_entry,
                match_status=status,
                is_flagged=status not in ("WHITELISTED_STRONG", "WHITELISTED_WEAK"),
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

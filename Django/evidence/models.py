from django.db import models
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator


# --------------------------------------------------------------------------
# 1) WHITELIST MODELS
# --------------------------------------------------------------------------
class AccessPointWhitelistGroup(models.Model):
    """
    Logical group of allowed APs for one SSID (and optionally a location).
    Example:
      name = "Hospital-WiFi Level 3"
      ssid = "Hospital-WiFi"
      strict = True  -> only the entries under this group are accepted
    """
    name = models.CharField(
        max_length=128,
        help_text="Friendly name, e.g. 'Ward 3A Wi-Fi'",
    )
    ssid = models.CharField(max_length=64, db_index=True)
    location = models.CharField(
        max_length=128,
        blank=True,
        null=True,
        help_text="Floor / ward / building",
    )
    default_security = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text="Expected security for this SSID, e.g. WPA2-PSK",
    )
    strict = models.BooleanField(
        default=False,
        help_text="If True, ONLY entries under this group are accepted for this SSID.",
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Uncheck to temporarily disable this whitelist group.",
    )

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "AP Whitelist Group"
        verbose_name_plural = "AP Whitelist Groups"
        indexes = [
            models.Index(fields=["ssid"]),
            models.Index(fields=["is_active"]),
        ]

    def __str__(self):
        return f"{self.name} ({self.ssid})"


class AccessPointWhitelistEntry(models.Model):
    """
    Actual identifiers (BSSID, security, channel, etc.) that belong to a whitelist group.

    The more fields you fill in, the stricter the matching becomes:
      - If a field is left blank/NULL here, it is ignored in matching.
      - If it is set here and differs on an observation, the matcher
        can return a specific *_MISMATCH evil-twin style status.
    """
    group = models.ForeignKey(
        AccessPointWhitelistGroup,
        on_delete=models.CASCADE,
        related_name="entries",
    )

    # exact AP MAC (optional for weak rules)
    bssid = models.CharField(
        max_length=17,
        blank=True,
        null=True,
        db_index=True,
        help_text=(
            "Exact AP MAC, e.g. AA:BB:CC:DD:EE:FF. "
            "Leave empty to allow any BSSID under this SSID."
        ),
    )

    # security / radio properties
    security = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text="Expected security (compared to ESP32 'security' field), e.g. WPA2-PSK.",
    )
    channel = models.IntegerField(
        blank=True,
        null=True,
        help_text="Expected channel for this AP. Leave blank to ignore.",
    )
    band = models.CharField(
        max_length=16,
        blank=True,
        null=True,
        help_text="Expected band label, e.g. '2.4GHz', '5GHz', '6GHz' (optional).",
    )

    vendor_oui = models.CharField(
        max_length=8,
        blank=True,
        null=True,
        help_text="Expected OUI prefix, e.g. 'F09FC2' (optional, from BSSID).",
    )

    # RSN / AKM / PMF expectations (all optional)
    rsn_text = models.CharField(
        max_length=128,
        blank=True,
        null=True,
        help_text="Expected RSN text, e.g. 'CCMP/CCMP'. Leave blank to ignore.",
    )
    akm_list = models.CharField(
        max_length=256,
        blank=True,
        null=True,
        help_text="Expected AKM list, e.g. 'PSK,SAE'. Leave blank to ignore.",
    )
    pmf_capable = models.BooleanField(
        default=False,
        help_text="Check if AP is expected to advertise PMF capable. Leave default if not used.",
    )
    pmf_required = models.BooleanField(
        default=False,
        help_text="Check if AP is expected to require PMF. Leave default if not used.",
    )

    is_active = models.BooleanField(
        default=True,
        help_text="Uncheck to disable this exact AP entry without deleting it.",
    )

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "AP Whitelist Entry"
        verbose_name_plural = "AP Whitelist Entries"
        indexes = [
            models.Index(fields=["bssid"]),
            models.Index(fields=["is_active"]),
        ]

    def __str__(self):
        return f"{self.group.ssid} - {self.bssid or 'ANY'}"


# --------------------------------------------------------------------------
# 2) UNIQUE UNREGISTERED / UNKNOWN AP REGISTRY
# --------------------------------------------------------------------------
class UnregisteredAP(models.Model):
    """
    Registry of unique unwhitelisted APs.

    Populated automatically when an observation's match_status is UNREGISTERED_AP.
    Each row represents a BSSID (or SSID+channel+OUI combo) that has been
    seen as unregistered at least once, with a running count and timestamps.
    """
    ssid = models.CharField(max_length=64, blank=True)
    bssid = models.CharField(
        max_length=17,
        blank=True,
        db_index=True,
        help_text="AP MAC if known, otherwise empty for SSID-only entries.",
    )
    oui = models.CharField(
        max_length=8,
        blank=True,
        help_text="First 3 bytes of BSSID, as hex (e.g. 'F09FC2').",
    )
    channel = models.IntegerField(
        blank=True,
        null=True,
        help_text="Most recently seen channel for this AP.",
    )

    first_seen = models.DateTimeField(help_text="When this unregistered AP was first seen.")
    last_seen = models.DateTimeField(help_text="When this unregistered AP was last seen.")

    last_device = models.ForeignKey(
        "devices.Device",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="unregistered_aps_last_seen",
        help_text="Last device that saw this AP.",
    )
    seen_count = models.PositiveIntegerField(default=0, help_text="How many times we've seen it.")

    # soft delete / acknowledgement
    is_active = models.BooleanField(
        default=True,
        help_text="Active = still of interest; False = acknowledged / suppressed.",
    )
    notes = models.TextField(
        blank=True,
        help_text="Operator notes / investigation outcome.",
    )

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-last_seen"]
        indexes = [
            models.Index(fields=["bssid"]),
            models.Index(fields=["ssid"]),
            models.Index(fields=["is_active"]),
        ]
        verbose_name = "Unregistered AP"
        verbose_name_plural = "Unregistered APs"

    def __str__(self):
        return f"{self.ssid or '(no SSID)'} / {self.bssid or 'no BSSID'}"


# --------------------------------------------------------------------------
# 3) OBSERVATIONS (ESP32 uploads)
# --------------------------------------------------------------------------
class AccessPointObservation(models.Model):
    """
    One observed AP (usually 1 row per BSSID per upload).
    The ESP32 now signs each record; we store signature + canonical for chain-of-custody.
    """
    device = models.ForeignKey(
        "devices.Device",
        on_delete=models.PROTECT,
        related_name="ap_observations",
        null=True,
        blank=True,
        help_text="Originating scanner / device",
    )

    # identifiers
    ssid = models.CharField(max_length=64, blank=True, null=True)
    bssid = models.CharField(max_length=17, db_index=True)
    oui = models.CharField(
        max_length=8,
        blank=True,
        null=True,
        help_text="First 3 bytes of BSSID, as hex (e.g. 'F09FC2').",
    )

    channel = models.PositiveIntegerField(
        default=1,
        validators=[MinValueValidator(1), MaxValueValidator(196)],
        help_text="Wi-Fi channel (1–196)",
    )
    band = models.CharField(
        max_length=16,
        blank=True,
        null=True,
        help_text="Optional band label, e.g. 2.4GHz / 5GHz / 6GHz.",
    )

    # signal / counters
    rssi_current = models.IntegerField(
        blank=True,
        null=True,
        help_text="Current RSSI (from ESP32: rssi_cur)",
    )
    rssi_best = models.IntegerField(
        blank=True,
        null=True,
        help_text="Best RSSI seen (from ESP32: rssi_best)",
    )
    beacons = models.IntegerField(
        blank=True,
        null=True,
        help_text="Number of beacons seen for this BSSID",
    )
    sensor_last_seen_ms = models.BigIntegerField(
        blank=True,
        null=True,
        help_text="ESP32 'last_seen_ms' (millis since start of capture).",
    )

    # security info
    security = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text="Security type detected by ESP32, e.g. WPA2-PSK, Open, WPA3-SAE",
    )
    rsn_text = models.CharField(
        max_length=128,
        blank=True,
        null=True,
        help_text="RSN column from ESP32, e.g. 'CCMP/CCMP' or '-'",
    )
    akm_list = models.CharField(
        max_length=256,
        blank=True,
        null=True,
        help_text="Comma-separated AKMs from ESP32, e.g. 'PSK,SAE'",
    )
    pmf_capable = models.BooleanField(default=False)
    pmf_required = models.BooleanField(default=False)

    # integrity/signature (aligned with apsentinel/views.py)
    canonical = models.TextField(
        blank=True,
        null=True,
        help_text="Exact canonical string that the ESP32 signed.",
    )
    hash_sha256 = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text="SHA-256 hex digest of the canonical string (device-sent).",
    )
    sig_alg = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text="Signature algorithm, e.g. 'ECDSA_P256_SHA256'.",
    )
    sig_r = models.CharField(max_length=130, blank=True, null=True)
    sig_s = models.CharField(max_length=130, blank=True, null=True)

    # timestamps
    sensor_ts = models.DateTimeField(
        blank=True,
        null=True,
        help_text="Device-reported timestamp (if you later send real UTC).",
    )
    server_ts = models.DateTimeField(
        default=timezone.now,
        help_text="Server ingest timestamp",
    )

    # whitelist match (snapshot at ingest)
    matched_group = models.ForeignKey(
        AccessPointWhitelistGroup,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="matched_observations",
        help_text="Which whitelist group matched this observation (by SSID).",
    )
    matched_entry = models.ForeignKey(
        AccessPointWhitelistEntry,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="matched_observations",
        help_text="Which specific entry (BSSID/security) matched.",
    )
    match_status = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text=(
            "Snapshot status at ingest. Possible values include: "
            "WHITELISTED_STRONG, WHITELISTED_WEAK, "
            "CHANNEL_MISMATCH, SECURITY_MISMATCH, VENDOR_MISMATCH, "
            "BAND_MISMATCH, RSN_MISMATCH, AKM_MISMATCH, PMF_MISMATCH, "
            "KNOWN_SSID_BUT_UNEXPECTED_AP, KNOWN_SSID_REJECTED, UNREGISTERED_AP."
        ),
    )

    # risk / flags
    similarity_score = models.FloatField(default=0.0)
    risk_score = models.FloatField(default=0.0)
    flags = models.JSONField(
        default=list,
        help_text="List of triggered alert flags, e.g. ['UNREGISTERED_AP']",
    )
    is_flagged = models.BooleanField(
        default=False,
        help_text="Set True if this observation should alert on dashboard.",
    )

    # bookkeeping
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    # 🔐 chain of custody
    prev_chain_hash = models.BinaryField(
        null=True,
        blank=True,
        help_text="Hash of previous observation for this device",
    )
    chain_hash = models.BinaryField(
        null=True,
        blank=True,
        help_text="Hash linking previous chain to this observation",
    )
    integrity_ok = models.BooleanField(
        default=True,
        help_text="Set False if later verification fails",
    )

    class Meta:
        indexes = [
            models.Index(fields=["ssid"]),
            models.Index(fields=["bssid"]),
            models.Index(fields=["server_ts"]),
            models.Index(fields=["device"]),
        ]
        verbose_name = "Access Point Observation"
        verbose_name_plural = "Access Point Observations"

    def __str__(self):
        return f"{self.ssid or '<hidden>'} / {self.bssid}"

    def chain_hex(self):
        """
        Return chain_hash as hex string for templates/admin.
        """
        if self.chain_hash:
            return self.chain_hash.hex()
        return ""

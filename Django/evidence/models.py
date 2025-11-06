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
      strict = True  -> only the entries under this group are allowed
    """
    name = models.CharField(max_length=128, help_text="Friendly name, e.g. 'Ward 3A Wi-Fi'")
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

    # CHANGED: make this toggleable in admin/UI
    is_active = models.BooleanField(
        default=True,
        help_text="Uncheck to temporarily disable this whitelist group (all its entries will be ignored in matching).",
    )

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "AP Whitelist Group"
        verbose_name_plural = "AP Whitelist Groups"
        indexes = [
            models.Index(fields=["ssid"]),
            models.Index(fields=["is_active"]),  # added for fast filtering
        ]

    def __str__(self):
        return f"{self.name} ({self.ssid})"


class AccessPointWhitelistEntry(models.Model):
    """
    Actual identifiers that belong to a whitelist group.
    """
    group = models.ForeignKey(
        AccessPointWhitelistGroup,
        on_delete=models.CASCADE,
        related_name="entries",
    )
    # exact AP MAC, optional if group allows any BSSID for this SSID
    bssid = models.CharField(
        max_length=17,
        blank=True,
        null=True,
        db_index=True,
        help_text="Exact AP MAC, e.g. AA:BB:CC:DD:EE:FF. Leave empty to allow any BSSID under this SSID.",
    )
    security = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text="Expected security (compared to ESP32 'security' field).",
    )
    channel = models.IntegerField(
        blank=True,
        null=True,
        help_text="Expected channel for this AP. Leave blank to ignore.",
    )
    vendor_oui = models.CharField(
        max_length=8,
        blank=True,
        null=True,
        help_text="OUI prefix, e.g. 'F09FC2' (optional, from BSSID).",
    )

    # CHANGED: make this toggleable too
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
            models.Index(fields=["is_active"]),  # for queries like 'active entries for this SSID'
        ]

    def __str__(self):
        return f"{self.group.ssid} - {self.bssid or 'ANY'}"


# --------------------------------------------------------------------------
# 2) OBSERVATIONS (ESP32 uploads)
# --------------------------------------------------------------------------
class AccessPointObservation(models.Model):
    """
    Observed Access Points (from scanners or ESP32 devices)
    One JSON upload from the ESP32 will typically create multiple of these rows.
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

    # integrity/signature
    canonical = models.TextField(
        blank=True,
        null=True,
        help_text="Exact canonical string that the ESP32 signed.",
    )
    hash_sha256 = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text="SHA-256 hex digest of canonical string, from ESP32.",
    )
    sig_alg = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text="Signature algorithm, e.g. 'ECDSA_P256_SHA256'.",
    )
    sig_r = models.CharField(max_length=80, blank=True, null=True)
    sig_s = models.CharField(max_length=80, blank=True, null=True)

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

    # whitelist match
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
        help_text="WHITELISTED_STRONG / WHITELISTED_WEAK / KNOWN_SSID_BUT_UNEXPECTED_AP / UNREGISTERED_AP",
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

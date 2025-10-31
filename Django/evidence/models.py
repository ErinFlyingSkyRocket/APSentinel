# evidence/models.py
from django.db import models
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator


class AccessPointWhitelist(models.Model):
    """
    Whitelisted Access Points (known legitimate APs)
    """
    ssid = models.CharField(max_length=64, db_index=True)
    bssid = models.CharField(
        max_length=17, blank=True, null=True, db_index=True,
        help_text="MAC address of the AP (optional if SSID-based trust only)",
    )
    vendor_oui = models.CharField(max_length=8, blank=True, null=True, help_text="OUI prefix, e.g. F0:9F:C2")
    expected_security = models.CharField(max_length=64, blank=True, null=True, help_text="Expected security type, e.g. WPA2-PSK")
    allowed_bands = models.CharField(max_length=32, blank=True, null=True, help_text="Comma-separated, e.g. '2.4GHz,5GHz,6GHz'")
    allowed_channels = models.CharField(max_length=128, blank=True, null=True, help_text="Comma-separated channel list, e.g. '1,6,11'")
    notes = models.TextField(blank=True, null=True)
    active = models.BooleanField(default=True)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("ssid", "bssid")]
        verbose_name = "Access Point Whitelist"
        verbose_name_plural = "Access Point Whitelist"

    def __str__(self):
        return f"{self.ssid} ({self.bssid or 'any BSSID'})"


class AccessPointObservation(models.Model):
    """
    Observed Access Points (from scanners or ESP32 devices)
    """

    # 🔗 Originating scanner / device
    device = models.ForeignKey(
        "devices.Device",
        on_delete=models.PROTECT,
        related_name="ap_observations",
        null=True,
        blank=True,
        help_text="Originating scanner / device",
    )

    # Raw scan result
    ssid = models.CharField(max_length=64, blank=True, null=True)
    bssid = models.CharField(max_length=17, db_index=True)
    channel = models.PositiveIntegerField(
        default=1,
        validators=[MinValueValidator(1), MaxValueValidator(196)],
        help_text="Wi-Fi channel (1–196)",
    )
    band = models.CharField(max_length=16, blank=True, null=True, help_text="e.g. 2.4GHz / 5GHz / 6GHz")
    security = models.CharField(max_length=64, blank=True, null=True, help_text="Security type detected")
    rssi = models.IntegerField(blank=True, null=True, help_text="Signal strength (dBm)")
    vendor_oui = models.CharField(max_length=8, blank=True, null=True)
    location_hint = models.CharField(max_length=128, blank=True, null=True)
    source_device = models.CharField(max_length=64, blank=True, null=True, help_text="Identifier of scanning device")
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)

    # ⏱️ Timestamps
    sensor_ts = models.DateTimeField(blank=True, null=True, help_text="Device-reported timestamp (UTC)")
    server_ts = models.DateTimeField(default=timezone.now, help_text="Server ingest timestamp")

    # 🔐 Hash-chain artifacts
    # If your compute_*hash helpers return HEX strings, switch to CharField(max_length=64).
    payload_hash = models.BinaryField(null=True, blank=True)
    prev_chain_hash = models.BinaryField(null=True, blank=True)
    chain_hash = models.BinaryField(null=True, blank=True)

    # Evaluation results
    is_whitelisted = models.BooleanField(default=False)
    matched_whitelist = models.ForeignKey(
        AccessPointWhitelist, null=True, blank=True, on_delete=models.SET_NULL, related_name="matches"
    )
    similarity_score = models.FloatField(default=0.0, help_text="0–1 similarity to whitelist SSID")
    risk_score = models.FloatField(default=0.0, help_text="0–100 computed risk score")
    flags = models.JSONField(default=list, help_text="List of triggered alert flags")
    is_flagged = models.BooleanField(default=False)

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

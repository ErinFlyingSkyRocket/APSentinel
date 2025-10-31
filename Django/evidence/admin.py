# evidence/admin.py
from django.contrib import admin
from .models import AccessPointWhitelist, AccessPointObservation


@admin.register(AccessPointWhitelist)
class AccessPointWhitelistAdmin(admin.ModelAdmin):
    list_display = (
        "ssid",
        "bssid",
        "expected_security",
        "allowed_bands",
        "allowed_channels",
        "active",
        "updated_at",
    )
    list_filter = ("active", "expected_security")
    search_fields = ("ssid", "bssid", "vendor_oui", "notes")


@admin.register(AccessPointObservation)
class AccessPointObservationAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "ssid",
        "bssid",
        "band",
        "channel",
        "security",
        "is_whitelisted",
        "is_flagged",
        "risk_score",
        "last_seen",
    )
    list_filter = ("is_flagged", "is_whitelisted", "band", "security")
    search_fields = ("ssid", "bssid", "source_device")
    readonly_fields = ("first_seen", "last_seen", "created_at", "updated_at")
    ordering = ("-is_flagged", "-risk_score", "-last_seen")

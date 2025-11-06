from django.contrib import admin
from .models import (
    AccessPointWhitelistGroup,
    AccessPointWhitelistEntry,
    AccessPointObservation,
)


# ---------------------------------------------------------------------
# Inline: show whitelist entries under each group
# ---------------------------------------------------------------------
class AccessPointWhitelistEntryInline(admin.TabularInline):
    model = AccessPointWhitelistEntry
    extra = 1
    # we expose is_active now so you can toggle rules directly
    fields = ("bssid", "security", "channel", "vendor_oui", "is_active")
    show_change_link = True


# ---------------------------------------------------------------------
# Whitelist Group admin
# ---------------------------------------------------------------------
@admin.register(AccessPointWhitelistGroup)
class AccessPointWhitelistGroupAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "ssid",
        "location",
        "default_security",
        "strict",
        "is_active",
        "updated_at",
    )
    list_filter = ("is_active", "strict", "default_security")
    search_fields = ("name", "ssid", "location")
    inlines = [AccessPointWhitelistEntryInline]
    ordering = ("ssid",)


# ---------------------------------------------------------------------
# Expose entries separately too
# ---------------------------------------------------------------------
@admin.register(AccessPointWhitelistEntry)
class AccessPointWhitelistEntryAdmin(admin.ModelAdmin):
    list_display = (
        "group",
        "bssid",
        "security",
        "channel",
        "vendor_oui",
        "is_active",
        "updated_at",
    )
    list_filter = ("is_active", "security")
    search_fields = (
        "bssid",
        "vendor_oui",
        "group__ssid",
        "group__name",
    )
    ordering = ("group", "bssid")


# ---------------------------------------------------------------------
# Observation admin
# ---------------------------------------------------------------------
@admin.register(AccessPointObservation)
class AccessPointObservationAdmin(admin.ModelAdmin):
    list_display = (
        "ssid",
        "bssid",
        "device",
        "channel",
        "security",
        "rssi_current",
        "match_status",
        "is_flagged",
        "risk_score",
        "server_ts",
    )
    list_filter = (
        "match_status",
        "security",
        "pmf_required",
        "is_flagged",
        "server_ts",
    )
    search_fields = (
        "ssid",
        "bssid",
        "device__name",   # your Device has 'name'
        "device__location",
        "canonical",
    )
    readonly_fields = (
        "server_ts",
        "created_at",
        "updated_at",
        "canonical",
        "hash_sha256",
        "sig_alg",
        "sig_r",
        "sig_s",
    )
    ordering = ("-server_ts",)
    raw_id_fields = ("device",)  # nice when you have lots of observations

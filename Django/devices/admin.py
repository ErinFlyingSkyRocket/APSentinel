from django.contrib import admin
from .models import Device

@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ("name", "location", "is_active", "last_seen", "enrolled_at")
    search_fields = ("name", "location", "description")
    list_filter = ("is_active", "location", "enrolled_at")

    # 👇 make MAC/OUI and timestamps read-only (admin can see, not change)
    readonly_fields = (
        "enrolled_at",
        "last_seen",
        "esp_mac",
        "esp_oui",
        "esp_mac_locked_at",
    )

    # Optional: make the detail screen a bit nicer, but not required
    fieldsets = (
        (None, {
            "fields": (
                "name",
                "description",
                "location",
                "is_active",
            )
        }),
        ("Keys & 2nd-factor", {
            "fields": (
                "pubkey_pem",
                "esp_mac",
                "esp_oui",
                "esp_mac_locked_at",
            )
        }),
        ("Timestamps", {
            "fields": (
                "enrolled_at",
                "last_seen",
            )
        }),
    )

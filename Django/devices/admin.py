from django.contrib import admin
from .models import Device

@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ("name", "location", "is_active", "last_seen", "enrolled_at")
    search_fields = ("name", "location", "description")
    list_filter = ("is_active", "location", "enrolled_at")
    readonly_fields = ("enrolled_at", "last_seen")

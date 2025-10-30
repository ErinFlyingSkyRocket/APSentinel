from django.contrib import admin
from .models import Device

@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ("name","is_active","enrolled_at")
    search_fields = ("name",)

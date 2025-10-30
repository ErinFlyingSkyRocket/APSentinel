from django.contrib import admin
from .models import Observation

@admin.register(Observation)
class ObservationAdmin(admin.ModelAdmin):
    list_display = ("id","device","ssid","bssid","server_ts")
    list_filter = ("ssid",)
    search_fields = ("ssid","bssid","device__name")
    readonly_fields = ("payload_hash","prev_chain_hash","chain_hash","device_sig","server_ts")
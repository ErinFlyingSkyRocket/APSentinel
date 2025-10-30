from django.db import models
from devices.models import Device

class Observation(models.Model):
    device = models.ForeignKey(Device, on_delete=models.PROTECT)
    ssid = models.CharField(max_length=64)
    bssid = models.CharField(max_length=17)
    rsn = models.JSONField(null=True, blank=True)
    rssi = models.IntegerField(null=True, blank=True)
    sensor_ts = models.DateTimeField()
    server_ts = models.DateTimeField(auto_now_add=True)
    payload_hash = models.BinaryField()
    prev_chain_hash = models.BinaryField(null=True, blank=True)
    chain_hash = models.BinaryField()
    device_sig = models.BinaryField()

    class Meta:
        indexes = [models.Index(fields=["ssid", "bssid", "server_ts"])]

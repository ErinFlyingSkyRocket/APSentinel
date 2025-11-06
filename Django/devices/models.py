from django.db import models
from django.utils import timezone
from datetime import timedelta

class Device(models.Model):
    name = models.CharField(max_length=64, unique=True)
    pubkey_pem = models.TextField()  # public key only (PEM)
    enrolled_at = models.DateTimeField(auto_now_add=True)

    # Admin-controlled: whether this device/sensor is allowed to be used
    # in whitelist/matching logic. Different from 'is_online'.
    is_active = models.BooleanField(
        default=True,
        help_text="Uncheck to disable this device's rules / ingestion without deleting it."
    )

    # Optional metadata (nullable = migration-friendly)
    description = models.TextField(blank=True, null=True)
    location = models.CharField(max_length=128, blank=True, null=True)

    # Last time we ingested a valid packet from this device
    last_seen = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.name

    @property
    def is_online(self) -> bool:
        """
        Derived ONLINE status = last_seen within 5 minutes.
        This is runtime/telemetry, not the admin 'is_active'.
        """
        if not self.last_seen:
            return False
        return timezone.now() - self.last_seen <= timedelta(minutes=5)

    class Meta:
        indexes = [
            models.Index(fields=["name"]),
            models.Index(fields=["is_active"]),
            models.Index(fields=["location"]),
            models.Index(fields=["last_seen"]),
        ]

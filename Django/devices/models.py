from django.db import models
from django.utils import timezone
from datetime import timedelta

class Device(models.Model):
    name = models.CharField(max_length=64, unique=True)

    # public key (PEM) for verifying signatures
    pubkey_pem = models.TextField(
        blank=True,
        null=True,
        help_text="Device's ECDSA public key in PEM format."
    )

    enrolled_at = models.DateTimeField(auto_now_add=True)

    # this is your "rule active/inactive" toggle
    is_active = models.BooleanField(
        default=True,
        help_text="Uncheck to disable this device’s uploads."
    )

    description = models.TextField(blank=True, null=True)
    location = models.CharField(max_length=128, blank=True, null=True)

    # updated whenever the device sends an observation
    last_seen = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.name

    @property
    def is_online(self):
        """
        True if this device has been seen in the last 10 minutes.
        This is what you'll show as 'Status'.
        """
        if not self.last_seen:
            return False
        return timezone.now() - self.last_seen <= timedelta(minutes=10)

    @property
    def rule_active(self):
        """
        Alias to make templates clearer.
        This is what you'll show as 'Rule Active'.
        """
        return self.is_active

    class Meta:
        indexes = [
            models.Index(fields=["name"]),
            models.Index(fields=["is_active"]),
            models.Index(fields=["location"]),
            models.Index(fields=["last_seen"]),
        ]

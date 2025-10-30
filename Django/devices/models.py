from django.db import models

class Device(models.Model):
    name = models.CharField(max_length=64, unique=True)
    pubkey_pem = models.TextField()  # public key only (PEM)
    enrolled_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    # Make these nullable to avoid default prompts on migration
    description = models.TextField(blank=True, null=True)
    location = models.CharField(max_length=128, blank=True, null=True)
    last_seen = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.name

    class Meta:
        indexes = [
            models.Index(fields=["name"]),
            models.Index(fields=["is_active"]),
            models.Index(fields=["location"]),
            models.Index(fields=["last_seen"]),
        ]

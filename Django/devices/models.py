from django.db import models

class Device(models.Model):
    name = models.CharField(max_length=120, unique=True)
    pubkey_pem = models.TextField()
    enrolled_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name

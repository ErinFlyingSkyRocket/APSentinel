from django import forms
from .models import AccessPointWhitelist

class AccessPointWhitelistForm(forms.ModelForm):
    class Meta:
        model = AccessPointWhitelist
        fields = [
            "ssid",
            "bssid",
            "vendor_oui",
            "expected_security",
            "allowed_bands",
            "allowed_channels",
            "notes",
            "active",
        ]
        widgets = {
            "notes": forms.Textarea(attrs={"rows": 3}),
        }

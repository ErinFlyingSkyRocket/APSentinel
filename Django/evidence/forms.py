# evidence/forms.py
from django import forms
from .models import (
    AccessPointWhitelistGroup,
    AccessPointWhitelistEntry,
)


class AccessPointWhitelistGroupForm(forms.ModelForm):
    class Meta:
        model = AccessPointWhitelistGroup
        fields = [
            "name",
            "ssid",
            "location",
            "default_security",
            "strict",
            "is_active",
        ]


class AccessPointWhitelistEntryForm(forms.ModelForm):
    class Meta:
        model = AccessPointWhitelistEntry
        fields = [
            "group",
            "bssid",
            "security",
            "channel",
            "vendor_oui",
            "is_active",
        ]
        widgets = {
            "vendor_oui": forms.TextInput(attrs={"placeholder": "e.g. F09FC2"}),
        }

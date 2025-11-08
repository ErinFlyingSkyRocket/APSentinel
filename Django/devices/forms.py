# devices/forms.py
from django import forms
from .models import Device


class DeviceForm(forms.ModelForm):
    class Meta:
        model = Device
        fields = [
            "name",
            "location",
            "description",
            "is_active",
            "is_revoked",
            "pubkey_pem",
            "key_algo",
        ]
        widgets = {
            "description": forms.Textarea(attrs={"rows": 3}),
            "pubkey_pem": forms.Textarea(attrs={"rows": 6}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # key is provisioned by device, so show but don’t let user edit
        self.fields["pubkey_pem"].disabled = True
        # algo too — normally set by ingest
        self.fields["key_algo"].disabled = True

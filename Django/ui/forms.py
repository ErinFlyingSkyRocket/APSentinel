from django import forms
from devices.models import Device

class DeviceForm(forms.ModelForm):
    class Meta:
        model = Device
        fields = ["name", "pubkey_pem", "is_active"]
        widgets = {
            "name": forms.TextInput(attrs={"class":"w","placeholder":"esp32-sensor-01"}),
            "pubkey_pem": forms.Textarea(attrs={"rows":8, "class":"w", "placeholder":"-----BEGIN PUBLIC KEY----- ..."}),
        }

    def clean_pubkey_pem(self):
        pem = self.cleaned_data["pubkey_pem"].strip()
        if not (pem.startswith("-----BEGIN PUBLIC KEY-----") and pem.endswith("-----END PUBLIC KEY-----")):
            raise forms.ValidationError("Please paste a valid PEM public key.")
        return pem

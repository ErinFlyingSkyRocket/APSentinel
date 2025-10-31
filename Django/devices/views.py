# devices/views.py
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import IntegrityError
from django.db.models import ProtectedError
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_http_methods

from evidence.models import AccessPointObservation  # ✅ updated
from .models import Device

# Crypto for key generation (ECDSA P-256)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


@login_required
def devices_view(request):
    """
    Simple read-only list of devices.
    Template: templates/devices/list.html
    """
    devices = Device.objects.all().order_by("id")
    return render(request, "devices/list.html", {"devices": devices})


@login_required
@require_http_methods(["GET", "POST"])
def add_device_view(request):
    """
    Single page that supports:
      - Generate Keypair (action=gen) -> shows keys on same page and pre-fills public key field
      - Add Device      (action=add) -> creates device with provided name/public key
        NOTE: We do NOT read 'is_active' from POST; new devices default to True.
    Template: templates/devices/add_device.html
    """
    ctx = {
        "public_pem": "",
        "private_pem": "",
        "generated": False,
    }

    # Determine available fields on Device to avoid passing unknown kwargs
    device_field_names = {f.name for f in Device._meta.get_fields()}

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()

        if action == "gen":
            # Generate ECDSA P-256 (secp256r1) keypair
            private_key = ec.generate_private_key(ec.SECP256R1())
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")

            # Return keys on the same page; pre-fill the Add form with the public key
            ctx.update({
                "public_pem": public_pem,
                "private_pem": private_pem,  # shown once; never stored
                "generated": True,
            })
            return render(request, "devices/add_device.html", ctx)

        elif action == "add":
            name = (request.POST.get("name") or "").strip()
            pubkey_pem = (request.POST.get("pubkey_pem") or "").strip()

            # Optional fields—only used if your Device model defines them
            location = (request.POST.get("location") or "").strip()
            description = (request.POST.get("description") or "").strip()

            if not name or not pubkey_pem:
                messages.error(request, "Name and public key are required.")
                return redirect("/ui/devices/add")

            try:
                create_kwargs = {
                    "name": name,
                    "pubkey_pem": pubkey_pem,
                    # Do NOT read is_active from POST; rely on model default=True
                    "is_active": True,
                }
                if "location" in device_field_names:
                    create_kwargs["location"] = location or None
                if "description" in device_field_names:
                    create_kwargs["description"] = description or None

                Device.objects.create(**create_kwargs)
                messages.success(request, f"Device '{name}' added.")
            except IntegrityError:
                messages.error(request, f"Device name '{name}' already exists.")
                return redirect("/ui/devices/add")

            return redirect("/ui/devices")

        else:
            messages.error(request, "Invalid action.")
            return redirect("/ui/devices/add")

    # GET
    return render(request, "devices/add_device.html", ctx)


@login_required
@require_http_methods(["GET", "POST"])
def edit_device_view(request, pk):
    device = get_object_or_404(Device, pk=pk)

    if request.method == "POST":
        device.name = request.POST.get("name", device.name)
        device.location = request.POST.get("location", device.location)
        device.description = request.POST.get("description", device.description)
        device.save()
        messages.success(request, f"Device '{device.name}' updated successfully.")
        return redirect("/ui/devices")

    return render(request, "devices/edit.html", {"device": device})


@login_required
@require_http_methods(["POST"])
def delete_device_view(request, pk: int):
    """
    Delete a device by primary key.
    Trigger from the devices list page.
    """
    dev = get_object_or_404(Device, pk=pk)
    try:
        dev.delete()
        messages.success(request, f"Device '{dev.name}' deleted.")
    except ProtectedError:
        # If AccessPointObservation has a FK to Device (recommended), count them:
        try:
            obs_count = AccessPointObservation.objects.filter(device=dev).count()
        except Exception:
            # Fallback if FK not present yet
            obs_count = 0
        messages.error(
            request,
            f"Cannot delete '{dev.name}': {obs_count} observation(s) still reference this device."
        )
    return redirect("/ui/devices")

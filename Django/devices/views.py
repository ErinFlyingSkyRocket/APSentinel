from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.db import IntegrityError
from evidence.models import Observation

from .models import Device

# Crypto for key generation (ECDSA P-256)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def devices_view(request):
    """
    Simple read-only list of devices.
    Template: templates/devices/list.html
    """
    devices = Device.objects.all().order_by("id")
    return render(request, "devices/list.html", {"devices": devices})


@require_http_methods(["GET", "POST"])
def add_device_view(request):
    """
    Single page that supports:
      - Generate Keypair (action=gen) -> shows keys on same page and pre-fills public key field
      - Add Device      (action=add) -> creates device with provided name/public key/active flag
    Template: templates/devices/add_device.html
    """
    ctx = {
        "public_pem": "",
        "private_pem": "",
        "generated": False,
    }

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
            is_active = bool(request.POST.get("is_active"))

            # Optional fields—only used if your Device model has them
            location = (request.POST.get("location") or "").strip()
            description = (request.POST.get("description") or "").strip()

            if not name or not pubkey_pem:
                messages.error(request, "Name and public key are required.")
                return redirect("/ui/devices/add")

            try:
                Device.objects.create(
                    name=name,
                    pubkey_pem=pubkey_pem,
                    is_active=is_active,
                    # keep these only if your model has them (null=True recommended):
                    location=location if hasattr(Device, "location") else None,
                    description=description if hasattr(Device, "description") else None,
                )
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
        count = Observation.objects.filter(device=dev).count()
        messages.error(
            request,
            f"Cannot delete '{dev.name}': {count} observation(s) still reference this device."
        )
    return redirect("/ui/devices")


@require_http_methods(["POST"])
def toggle_active_view(request, pk: int):
    """
    Flip is_active True/False (simple toggle) from the devices list page.
    """
    dev = get_object_or_404(Device, pk=pk)
    dev.is_active = not dev.is_active
    dev.save(update_fields=["is_active"])
    messages.success(request, f"Device '{dev.name}' active = {dev.is_active}.")
    return redirect("/ui/devices")

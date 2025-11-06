# devices/views.py
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import IntegrityError
from django.db.models import ProtectedError
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_http_methods

from evidence.models import AccessPointObservation  # FK check for delete
from .models import Device

# Crypto for key generation (ECDSA P-256)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


@login_required
def devices_view(request):
    """
    List all registered devices.
    """
    devices = Device.objects.all().order_by("id")
    return render(request, "devices/list.html", {"devices": devices})


@login_required
@require_http_methods(["GET", "POST"])
def add_device_view(request):
    """
    - action=gen: generate keypair and show on same page
    - action=add: create device (now supports is_active toggle)
    """
    ctx = {
        "public_pem": "",
        "private_pem": "",
        "generated": False,
    }

    device_field_names = {f.name for f in Device._meta.get_fields()}

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()

        # 1) generate keypair
        if action == "gen":
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

            ctx.update({
                "public_pem": public_pem,
                "private_pem": private_pem,
                "generated": True,
            })
            return render(request, "devices/add_device.html", ctx)

        # 2) add device
        elif action == "add":
            name = (request.POST.get("name") or "").strip()
            pubkey_pem = (request.POST.get("pubkey_pem") or "").strip()
            location = (request.POST.get("location") or "").strip()
            description = (request.POST.get("description") or "").strip()
            # read the checkbox
            is_active = "is_active" in request.POST

            if not name or not pubkey_pem:
                messages.error(request, "Name and public key are required.")
                return redirect("/ui/devices/add")

            try:
                create_kwargs = {
                    "name": name,
                    "pubkey_pem": pubkey_pem,
                    "is_active": is_active,
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
    """
    Edit existing device, including enabling/disabling it.
    """
    device = get_object_or_404(Device, pk=pk)

    if request.method == "POST":
        device.name = request.POST.get("name", device.name)
        device.location = request.POST.get("location", device.location)
        device.description = request.POST.get("description", device.description)
        # checkbox: if it’s absent (unchecked), it won’t be in POST
        device.is_active = "is_active" in request.POST
        device.save()

        messages.success(request, f"Device '{device.name}' updated successfully.")
        return redirect("/ui/devices")

    return render(request, "devices/edit.html", {"device": device})


@login_required
@require_http_methods(["POST"])
def delete_device_view(request, pk: int):
    """
    Delete a device; if it has observations tied to it, show an error.
    """
    dev = get_object_or_404(Device, pk=pk)
    try:
        dev.delete()
        messages.success(request, f"Device '{dev.name}' deleted.")
    except ProtectedError:
        try:
            obs_count = AccessPointObservation.objects.filter(device=dev).count()
        except Exception:
            obs_count = 0
        messages.error(
            request,
            f"Cannot delete '{dev.name}': {obs_count} observation(s) still reference this device."
        )
    return redirect("/ui/devices")

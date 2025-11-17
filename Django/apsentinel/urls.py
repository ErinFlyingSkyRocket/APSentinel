# apsentinel/urls.py
from django.contrib import admin
from django.urls import path
from django.contrib.auth import views as auth_views

from .views import health, ingest_observation, hashchain_analysis
from ui.views import dashboard, observations, observation_detail, observations_unwhitelisted, unregistered_aps, ap_activity
from devices.views import devices_view, add_device_view, delete_device_view, edit_device_view
from evidence.views import latest_observation, whitelist_list, whitelist_add, whitelist_edit, whitelist_delete, whitelist_entry_delete, whitelist_add_from_observation

urlpatterns = [

    # --------------------------------------------------------------
    # Dashboard / Home
    # --------------------------------------------------------------
    path("", dashboard, name="dashboard"),
    path("admin/", admin.site.urls),

    # --------------------------------------------------------------
    # API (ESP32 ingest / health / automation)
    # --------------------------------------------------------------
    path("api/health/", health, name="api_health"),
    path("api/ingest/observation", ingest_observation, name="api_ingest_observation"),
    path("api/ingest/esp32/", ingest_observation, name="api_ingest_esp32"),
    path("api/latest-observation", latest_observation, name="latest_observation"),

    # --------------------------------------------------------------
    # Observations UI
    # --------------------------------------------------------------
    path("ui/observations", observations, name="observations"),
    path("ui/observations/<int:pk>", observation_detail, name="observation_detail"),
    path("ui/observations/unwhitelisted", observations_unwhitelisted, name="observations_unwhitelisted"),
    path("ui/unregistered-aps", unregistered_aps, name="unregistered_aps"),
    path("ui/unregistered-aps/add/<int:obs_id>", whitelist_add_from_observation, name="unregistered_add_to_whitelist"),
    path("ui/ap-activity", ap_activity, name="ap_activity"),

    # --------------------------------------------------------------
    # Hashchain Verification UI
    # --------------------------------------------------------------
    path("ui/hashchain", hashchain_analysis, name="hashchain_analysis"),

    # --------------------------------------------------------------
    # Devices UI
    # --------------------------------------------------------------
    path("ui/devices", devices_view, name="devices"),
    path("ui/devices/add", add_device_view, name="device_add"),
    path("ui/devices/<int:pk>/delete", delete_device_view, name="device_delete"),
    path("ui/devices/<int:pk>/edit", edit_device_view, name="edit_device"),

    # --------------------------------------------------------------
    # Whitelist UI
    # --------------------------------------------------------------
    path("ui/whitelist", whitelist_list, name="whitelist_list"),
    path("ui/whitelist/add", whitelist_add, name="whitelist_add"),
    path("ui/whitelist/<int:pk>/edit", whitelist_edit, name="whitelist_edit"),
    path("ui/whitelist/<int:pk>/delete", whitelist_delete, name="whitelist_delete"),
    path("ui/whitelist/entry/<int:pk>/delete", whitelist_entry_delete, name="whitelist_entry_delete"),

    # --------------------------------------------------------------
    # Authentication
    # --------------------------------------------------------------
    path("accounts/login/", auth_views.LoginView.as_view(template_name="registration/login.html"), name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
]

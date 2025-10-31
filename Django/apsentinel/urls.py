# apsentinel/urls.py
from django.contrib import admin
from django.urls import path

from .views import health, ingest_observation

# UI views
from ui.views import dashboard, observations, observation_detail
from devices.views import devices_view, add_device_view, delete_device_view, edit_device_view
from evidence.views import latest_observation, whitelist_list, whitelist_add, whitelist_edit, whitelist_delete


from django.contrib.auth import views as auth_views

urlpatterns = [
    # Home / Dashboard
    path("", dashboard, name="dashboard"),

    # Admin
    path("admin/", admin.site.urls),

    # API
    path("api/health/", health, name="api_health"),
    path("api/ingest/observation", ingest_observation, name="api_ingest_observation"),
    path("api/latest-observation", latest_observation, name="latest_observation"),

    # UI - Observations
    path("ui/observations", observations, name="observations"),
    path("ui/observations/<int:pk>", observation_detail, name="observation_detail"),

    # UI - Devices
    path("ui/devices", devices_view, name="devices"),
    path("ui/devices/add", add_device_view, name="device_add"),
    path("ui/devices/<int:pk>/delete", delete_device_view, name="device_delete"),
    path("ui/devices/<int:pk>/edit", edit_device_view, name="edit_device"),

    # UI – Whitelist
    path("ui/whitelist", whitelist_list, name="whitelist_list"),
    path("ui/whitelist/add", whitelist_add, name="whitelist_add"),
    path("ui/whitelist/<int:pk>/edit", whitelist_edit, name="whitelist_edit"),
    path("ui/whitelist/<int:pk>/delete", whitelist_delete, name="whitelist_delete"),

    # Auth
    path("accounts/login/",  auth_views.LoginView.as_view(template_name="registration/login.html"), name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
]

from django.contrib import admin
from django.urls import path
from .views import health, ingest_observation

from django.contrib.auth import views as auth_views
from ui.views import dashboard, observations, observation_detail, devices_view
from devices.views import devices_view, add_device_view, delete_device_view, toggle_active_view


urlpatterns = [
    path("", dashboard, name="dashboard"),
    path("admin/", admin.site.urls),

    # API
    path("api/health/", health),
    path("api/ingest/observation", ingest_observation),

    # UI
    path("ui/observations", observations),
    path("ui/observations/<int:pk>", observation_detail),
    path("ui/devices", devices_view),
    path("ui/devices/add", add_device_view, name="add_device"),
    path("ui/devices/<int:pk>/delete", delete_device_view, name="delete_device"),
    path("ui/devices/<int:pk>/toggle", toggle_active_view, name="toggle_device"),

    path("accounts/login/",  auth_views.LoginView.as_view(template_name="registration/login.html"), name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
]

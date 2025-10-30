from django.contrib import admin
from django.urls import path
from .views import health, ingest_observation
from ui.views import dashboard, observations, observation_detail, devices_view

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
]

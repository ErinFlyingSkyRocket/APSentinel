from django.contrib import admin
from django.urls import path
from .views import health, ingest_observation
from evidence.views import latest_observation

urlpatterns = [
    path("", health, name="root"),
    path("admin/", admin.site.urls),
    path("api/health/", health),
    path("api/observations/latest", latest_observation),
]

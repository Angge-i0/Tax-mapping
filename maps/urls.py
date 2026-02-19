from django.urls import path
from .views import geojson_data

urlpatterns = [
    path('api/geojson/', geojson_data),
]

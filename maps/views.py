from django.http import JsonResponse
from functools import wraps
import json
from django.conf import settings
import os


def api_login_required(view_func):
    """
    Like @login_required but returns JSON 401 instead of redirecting to a login page.
    Apply this to all API views that require authentication.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse(
                {'error': 'Authentication required.'},
                status=401
            )
        return view_func(request, *args, **kwargs)
    return wrapper


@api_login_required
def geojson_data(request):
    file_path = os.path.join(settings.BASE_DIR, 'maps/static/maps/nasugbu.geojson')

    with open(file_path) as f:
        data = json.load(f)

    return JsonResponse(data)

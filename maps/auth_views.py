import json
import uuid
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import ensure_csrf_cookie


@ensure_csrf_cookie
@require_http_methods(["GET"])
def auth_check(request):
    if request.user.is_authenticated:
        return JsonResponse({
            'authenticated': True,
            'username': request.user.username,
            'is_staff': request.user.is_staff,
        })
    return JsonResponse({'authenticated': False, 'username': None, 'is_staff': False})


@require_http_methods(["POST"])
def login_view(request):
    try:
        body = json.loads(request.body)
        role = body.get('role', 'admin')
        password = body.get('password', '').strip()
    except (json.JSONDecodeError, AttributeError):
        return JsonResponse({'error': 'Invalid JSON body.'}, status=400)

    if not password:
        return JsonResponse({'error': 'Password is required.'}, status=400)

    if role == 'admin':
        id_number = body.get('id_number', '').strip()
        if not id_number:
            return JsonResponse({'error': 'ID Number is required.'}, status=400)
        user = authenticate(request, username=id_number, password=password)
    else:
        email = body.get('email', '').strip()
        if not email:
            return JsonResponse({'error': 'Email address is required.'}, status=400)
        try:
            user_obj = User.objects.get(email=email)
            user = authenticate(request, username=user_obj.username, password=password)
        except User.DoesNotExist:
            user = None
        except User.MultipleObjectsReturned:
            return JsonResponse({'error': 'Multiple accounts found with this email.'}, status=400)

    if user is None:
        return JsonResponse({'error': 'Invalid credentials. Please try again.'}, status=401)

    login(request, user)
    return JsonResponse({'authenticated': True, 'username': user.username, 'is_staff': user.is_staff})


@require_http_methods(["POST"])
def logout_view(request):
    logout(request)
    return JsonResponse({'authenticated': False})


@require_http_methods(["POST"])
def register_view(request):
    try:
        body = json.loads(request.body)
        role = body.get('role', 'user')
        password = body.get('password', '').strip()
        confirm_password = body.get('confirm_password', '').strip()
    except (json.JSONDecodeError, AttributeError):
        return JsonResponse({'error': 'Invalid JSON body.'}, status=400)

    if not password:
        return JsonResponse({'error': 'Password is required.'}, status=400)
    if password != confirm_password:
        return JsonResponse({'error': 'Passwords do not match.'}, status=400)
    if len(password) < 6:
        return JsonResponse({'error': 'Password must be at least 6 characters.'}, status=400)

    if role == 'admin':
        id_number = body.get('id_number', '').strip()
        name = body.get('name', '').strip()
        email = body.get('email', '').strip()

        if not id_number:
            return JsonResponse({'error': 'ID Number is required.'}, status=400)
        if not name:
            return JsonResponse({'error': 'Name is required.'}, status=400)
        if not email:
            return JsonResponse({'error': 'Email address is required.'}, status=400)
        if User.objects.filter(username=id_number).exists():
            return JsonResponse({'error': 'An account with this ID Number already exists.'}, status=400)

        user = User.objects.create_user(username=id_number, email=email, password=password)
        user.is_staff = True
        parts = name.strip().split(' ', 1)
        user.first_name = parts[0]
        if len(parts) > 1:
            user.last_name = parts[1]
        user.save()
    else:
        email = body.get('email', '').strip()
        if not email:
            return JsonResponse({'error': 'Email address is required.'}, status=400)
        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'An account with this email already exists.'}, status=400)

        username = email
        if User.objects.filter(username=username).exists():
            username = email.split('@')[0] + '_' + str(uuid.uuid4())[:8]

        user = User.objects.create_user(username=username, email=email, password=password)

    login(request, user)
    return JsonResponse({'authenticated': True, 'username': user.username, 'is_staff': user.is_staff})


# ── Admin: User management ─────────────────────────────────────────────────

def _user_to_dict(u):
    return {
        'id': u.id,
        'username': u.username,
        'full_name': f"{u.first_name} {u.last_name}".strip() or u.username,
        'role': 'Admin' if u.is_staff else 'Citizen',
        'email': u.email,
        'is_active': u.is_active,
    }


@require_http_methods(["GET", "POST"])
def users_view(request):
    """Admin only: list users (GET) or create a user (POST, no auto-login)."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)
    if not request.user.is_staff:
        return JsonResponse({'error': 'Admin access required.'}, status=403)

    if request.method == 'GET':
        users = [_user_to_dict(u) for u in User.objects.all().order_by('date_joined')]
        return JsonResponse({'users': users})

    # POST — create user without logging them in
    try:
        body = json.loads(request.body)
        role = body.get('role', 'citizen')
        password = body.get('password', '').strip()
    except (json.JSONDecodeError, AttributeError):
        return JsonResponse({'error': 'Invalid JSON body.'}, status=400)

    if not password or len(password) < 6:
        return JsonResponse({'error': 'Password must be at least 6 characters.'}, status=400)

    if role == 'admin':
        id_number = body.get('id_number', '').strip()
        name = body.get('name', '').strip()
        email = body.get('email', '').strip()

        if not id_number:
            return JsonResponse({'error': 'ID Number is required.'}, status=400)
        if User.objects.filter(username=id_number).exists():
            return JsonResponse({'error': 'ID Number already in use.'}, status=400)

        new_user = User.objects.create_user(username=id_number, email=email, password=password)
        new_user.is_staff = True
        if name:
            parts = name.split(' ', 1)
            new_user.first_name = parts[0]
            if len(parts) > 1:
                new_user.last_name = parts[1]
        new_user.save()
    else:
        email = body.get('email', '').strip()
        if not email:
            return JsonResponse({'error': 'Email is required.'}, status=400)
        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email already in use.'}, status=400)

        username = email.split('@')[0]
        if User.objects.filter(username=username).exists():
            username = email.split('@')[0] + '_' + str(uuid.uuid4())[:8]

        new_user = User.objects.create_user(username=username, email=email, password=password)

    return JsonResponse({'success': True, 'user': _user_to_dict(new_user)}, status=201)


@require_http_methods(["DELETE"])
def delete_user(request, user_id):
    """Admin only: delete a user by ID."""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)
    if not request.user.is_staff:
        return JsonResponse({'error': 'Admin access required.'}, status=403)

    try:
        target = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found.'}, status=404)

    if target == request.user:
        return JsonResponse({'error': 'Cannot delete your own account.'}, status=400)

    target.delete()
    return JsonResponse({'success': True})

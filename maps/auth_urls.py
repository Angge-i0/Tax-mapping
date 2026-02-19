from django.urls import path
from . import auth_views

urlpatterns = [
    path('login/', auth_views.login_view, name='auth_login'),
    path('logout/', auth_views.logout_view, name='auth_logout'),
    path('check/', auth_views.auth_check, name='auth_check'),
    path('register/', auth_views.register_view, name='auth_register'),
    path('users/', auth_views.users_view, name='users_view'),
    path('users/<int:user_id>/', auth_views.delete_user, name='delete_user'),
]

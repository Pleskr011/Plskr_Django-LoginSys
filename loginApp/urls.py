# loginApp/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('api/register/', views.user_create),
    path('api/users/', views.user_list),
    path('api/user/', views.user_detail),
    path('api/auth/', views.auth_view),
    path('api/auth/check/', views.check_session),
    path('api/login/', views.login_view),
    path('api/logout/', views.logout_view),
    path('api/recovery/', views.send_recovery_email),
    path('api/recovery/check/', views.check_recovery_token),
    path('api/recovery/reset/', views.reset_password),
    path('api/mfa/activate/', views.activateMFA),
    path('api/mfa/activate/check/', views.verifyOTP),
    
]
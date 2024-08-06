from django.urls import path
from .views import (RegisterView, ActivateAccountView, ResendActivationEmailView,
                    DeactivateUserView, DeleteUserView, LoginView, LogoutView)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('activate/<uuid:token>/',
         ActivateAccountView.as_view(), name='activate_account'),
    path('resend-activation/',
         ResendActivationEmailView.as_view(), name='resend_activation_email'),
    path('deactivate/<uuid:user_id>/',
         DeactivateUserView.as_view(), name='deactivate_user'),
    path('delete/<uuid:user_id>/', DeleteUserView.as_view(), name='delete_user'),
]

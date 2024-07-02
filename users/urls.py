from django.urls import path
from .views import PostView, GetView, ResetPasswordView

urlpatterns = [
    path('build/<str:action>/', PostView.as_view(), name='register'),
    path('fetch/<str:action>/<uidb64>/<token>/',
         GetView.as_view(), name='activate-account'),
    path('build/<str:action>/<uidb64>/<token>/',
         PostView.as_view(), name='forget-account'),
    path('reset-password/<uidb64>/<token>/',
         ResetPasswordView.as_view(), name='reset-password'),
]

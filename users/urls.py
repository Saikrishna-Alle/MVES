from django.urls import path
from .views import PostView, GetView

urlpatterns = [
    path('api/<str:action>/', PostView.as_view(), name='register'),
    path('api/<str:action>/<uidb64>/<token>/',
         GetView.as_view(), name='activate-account'),
]

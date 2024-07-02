from django.urls import path
from .views import PostView, GetView

urlpatterns = [
    path('build/<str:action>/', PostView.as_view(), name='create'),
    path('fetch/<str:action>/',
         GetView.as_view(), name='fetch'),
    path('fetch/<str:action>/<str:pk>/',
         GetView.as_view(), name='fetch-by-id'),
    path('fetch/<str:action>/<uidb64>/<token>/',
         GetView.as_view(), name='activate-account'),
    path('build/<str:action>/<uidb64>/<token>/',
         PostView.as_view(), name='forget-account'),
]

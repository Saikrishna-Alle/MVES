from django.urls import path
from .views import PostView, GetView, PatchView, TerminateView

urlpatterns = [
    path('build/<str:action>/', PostView.as_view(), name='create'),
    path('build/<str:action>/<str:pk>/', PostView.as_view(), name='create-id'),
    path('build/<str:action>/<uidb64>/<token>/',
         PostView.as_view(), name='forget-account'),
    path('fetch/<str:action>/',
         GetView.as_view(), name='fetch'),
    path('fetch/<str:action>/<str:pk>/',
         GetView.as_view(), name='fetch-by-id'),
    path('fetch/<str:action>/<uidb64>/<token>/',
         GetView.as_view(), name='activate-account'),
    path('modify/users/<str:pk>/', PatchView.as_view(),
         {'action': 'users'}, name='patch_user'),
    path('terminate/users/<str:pk>/', TerminateView.as_view(),
         {'action': 'users'}, name='terminate_user'),
]

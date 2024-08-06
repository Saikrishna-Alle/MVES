from django.urls import path
from .views import CompleteAuthView

urlpatterns = [
    path('auth/<str:action>/', CompleteAuthView.as_view(), name='auth'),
    path('auth/<str:action>/<uuid:token>/',
         CompleteAuthView.as_view(), name='auth_by_token')
]

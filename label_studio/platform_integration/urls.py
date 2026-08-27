from django.urls import path

from .views import (
    ManagedProjectBindAPIView,
    ManagedProjectCreateAPIView,
    ManagedProjectDeactivateAPIView,
    platform_login,
)


urlpatterns = [
    path('auth/platform/', platform_login, name='platform-login'),
    path('api/platform/projects/', ManagedProjectCreateAPIView.as_view(), name='platform-project-create'),
    path('api/platform/projects/<int:pk>/bind/', ManagedProjectBindAPIView.as_view(), name='platform-project-bind'),
    path('api/platform/projects/<int:pk>/deactivate/', ManagedProjectDeactivateAPIView.as_view(), name='platform-project-deactivate'),
]

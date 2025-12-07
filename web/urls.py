from django.urls import path
from .views import RegisterView, LoginView, TokenInfoView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    #path('token/info/', TokenInfoView.as_view(), name='token_info'),
]

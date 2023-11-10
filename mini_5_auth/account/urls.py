from django.urls import path

from account.views import UserAuthView

urlpatterns = [
    path('user-auth/', UserAuthView.as_view()),
]

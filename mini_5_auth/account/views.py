from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from rest_framework import mixins
from rest_framework.response import Response
from rest_framework.request import Request

from account.models import User


class GetUserMixin:
    def get(self, request, *args, **kwargs):
        print(request.user)
        print(request.auth)
        return Response({})


class UserAuthView(
    GenericAPIView,
    GetUserMixin,
):
    pass

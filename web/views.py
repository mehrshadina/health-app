from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from drf_spectacular.utils import extend_schema

from .models import User
from .serializers import (
    RegisterSerializer, LoginSerializer,
    TokenResponseSerializer, MessageResponseSerializer,
    ErrorResponseSerializer, TokenInfoSerializer
)

import datetime


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="ثبت‌نام کاربر جدید",
        description="این API برای ثبت‌نام کاربر جدید استفاده می‌شود.",
        request=RegisterSerializer,
        responses={
            201: MessageResponseSerializer,
            400: ErrorResponseSerializer
        }
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"error": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data.get('email')
        password = serializer.validated_data.get('password')
        first_name = serializer.validated_data.get('first_name', '')
        last_name = serializer.validated_data.get('last_name', '')
        #phone_number = serializer.validated_data.get('phone_number', '')

        if User.objects.filter(email=email).exists():
            return Response({"error": "Email already taken"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )
        #user.phone_number = phone_number
        user.save()

        return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="ورود کاربر",
        description="این API برای ورود کاربر و دریافت JWT Token استفاده می‌شود.",
        request=LoginSerializer,
        responses={
            200: TokenResponseSerializer,
            401: ErrorResponseSerializer
        }
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        email = serializer.validated_data.get('email')
        password = serializer.validated_data.get('password')

        user = authenticate(email=email, password=password)

        if user:
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }, status=status.HTTP_200_OK)

        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


class TokenInfoView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="دریافت اطلاعات توکن",
        description="این API اطلاعات مربوط به توکن دسترسی کاربر را برمی‌گرداند.",
        responses={
            200: TokenInfoSerializer,
            400: ErrorResponseSerializer
        }
    )
    def get(self, request):
        try:
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return Response({"error": "No token provided"}, status=status.HTTP_400_BAD_REQUEST)

            token_str = auth_header.split(" ")[1]
            token = AccessToken(token_str)

            exp_time = datetime.datetime.fromtimestamp(token["exp"])
            remaining_time = exp_time - datetime.datetime.now()
            remaining_seconds = int(remaining_time.total_seconds())

            return Response({
                "remaining_time": f"{remaining_seconds} seconds",
                "expires_at": exp_time.strftime("%Y-%m-%d %H:%M:%S")
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": "Invalid token", "details": str(e)}, status=status.HTTP_400_BAD_REQUEST)

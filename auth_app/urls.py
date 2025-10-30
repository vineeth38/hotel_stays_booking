from django.urls import path
from .import views
urlpatterns=[
    path("",view=views.sample),
    path("Signup/",view=views.Signup),
    path("verifyOtp/",view=views.VerifyOTP),
    path("login/",view=views.login),
    path("logout/",view=views.logout),
    path("booking/create/",view=views.create_booking),
    path("get_bookings/",view=views.get_bookings),
    path("auth/check/",view=views.auth_check)
]
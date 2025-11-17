from django.db import models
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

# Create your models here.
class UserManager(BaseUserManager):
    def create_user(self, email, password=None):
        if not email:
            raise ValueError("Users must have an email address")
        user = self.model(email=self.normalize_email(email))
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        user = self.create_user(email, password)
        user.is_admin = True
        user.save(using=self._db)
        return user

class Users(AbstractBaseUser):
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    is_admin = models.BooleanField(default=False)
    name = models.CharField(max_length=150, blank=True)
    city = models.CharField(max_length=100, blank=True)
    mobile = models.CharField(max_length=20, blank=True)

    USERNAME_FIELD = 'email'  # <--- Required!
    REQUIRED_FIELDS = []       # <--- Required by Django
    objects = UserManager()

    class Meta:
        db_table = 'auth_app_users'  # your existing table
# class Users(AbstractBaseUser):
#     email = models.EmailField(unique=True)
#     name = models.CharField(max_length=150, blank=True)
#     city = models.CharField(max_length=100, blank=True)
#     mobile = models.CharField(max_length=20, blank=True)
#     password = models.CharField(max_length=256,null=False)

# class Users(models.Model):
#     email = models.EmailField(unique=True)
#     name = models.CharField(max_length=150, blank=True)
#     city = models.CharField(max_length=100, blank=True)
#     mobile = models.CharField(max_length=20, blank=True)
#     password = models.CharField(max_length=256,null=False)



class Booking(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='bookings'
    )
    hotel_name = models.CharField(max_length=255)
    check_in = models.DateField()
    check_out = models.DateField()
    room_type = models.CharField(max_length=100)
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    city = models.CharField(max_length=100,default="Unknown")
    dp = models.CharField(max_length=500,default="Unknown")
    # def __str__(self):
    #     return f"{self.user.email} - {self.hotel_name} ({self.check_in} to {self.check_out})"

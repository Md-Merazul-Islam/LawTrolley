from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
now = timezone.now()


class Role(models.TextChoices):
    ADMIN = 'admin', 'Admin'
    MANAGER = 'manager', 'Manager'
    USER = 'user', 'User'

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    is_verified = models.BooleanField(default=False)
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.USER, null=True, blank=True)
    address = models.CharField(max_length=255, null=True, blank=True)
    phone_number = models.CharField(max_length=15, null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

class UserProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6,null=True, blank=True)
    otp_created_at = models.DateTimeField(auto_now_add=True)
    
    def is_otp_expired(self):
        if self.otp_created_at:
            return timezone.now() > self.otp_created_at + timezone.timedelta(minutes=5)
        return True
    
    def __str__(self):
        return f"Profile of {self.user.email}"
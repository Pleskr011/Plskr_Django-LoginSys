from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _

# Create your models here.

class CustomUser(AbstractUser):
    username = None
    email = models.EmailField(_("email address"), unique=True)
    MFA_code = models.CharField(max_length=128, blank=True)
    OTP_recovery=models.CharField(max_length=128, blank=True)
    secret_key = models.CharField(max_length=128, blank=True)
    isMfaEnabled = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email
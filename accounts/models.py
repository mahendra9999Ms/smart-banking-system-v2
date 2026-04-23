from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone
import random, hashlib


def generate_account_number():
    return "ASB" + str(random.randint(100000000, 999999999))


class UserProfile(models.Model):
    ACCOUNT_STATUS = [
        ('PENDING',  'Pending Approval'),
        ('ACTIVE',   'Active'),
        ('BLOCKED',  'Blocked'),
        ('REJECTED', 'Rejected'),
    ]
    user           = models.OneToOneField(User, on_delete=models.CASCADE)
    account_number = models.CharField(max_length=12, unique=True, blank=True)
    balance        = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    account_status = models.CharField(max_length=10, choices=ACCOUNT_STATUS, default='PENDING')

    full_name = models.CharField(max_length=100, blank=True, default='')
    email     = models.EmailField(blank=True, default='')
    phone     = models.CharField(max_length=15, blank=True, default='')

    # 4-digit PIN (SHA-256 hashed) for step-up auth
    pin_hash  = models.CharField(max_length=64, blank=True, default='')

    # Behavioral profile
    average_transaction_amount   = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    usual_transaction_hour_start = models.IntegerField(default=9)
    usual_transaction_hour_end   = models.IntegerField(default=18)

    # Progressive login lock
    failed_login_attempts = models.IntegerField(default=0)
    locked_until          = models.DateTimeField(null=True, blank=True)

    # Admin approval tracking
    approved_by      = models.ForeignKey(User, null=True, blank=True,
                            on_delete=models.SET_NULL, related_name='approved_users')
    approved_at      = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(blank=True, default='')

    def save(self, *args, **kwargs):
        if not self.account_number:
            self.account_number = generate_account_number()
        super().save(*args, **kwargs)

    # PIN helpers
    def set_pin(self, raw_pin):
        self.pin_hash = hashlib.sha256(raw_pin.encode()).hexdigest()

    def check_pin(self, raw_pin):
        return self.pin_hash == hashlib.sha256(raw_pin.encode()).hexdigest()

    # Lock helpers
    def is_locked(self):
        return bool(self.locked_until and timezone.now() < self.locked_until)

    def lock_seconds_remaining(self):
        if self.locked_until:
            return max(0, int((self.locked_until - timezone.now()).total_seconds()))
        return 0

    def __str__(self):
        return f"{self.user.username} [{self.account_status}]"


class AuditLog(models.Model):
    actor     = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='audit_actions')
    action    = models.CharField(max_length=255)
    target    = models.CharField(max_length=255, blank=True)
    details   = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.actor} — {self.action}"

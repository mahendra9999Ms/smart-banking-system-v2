import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class Transaction(models.Model):
    # ── Status lifecycle ─────────────────────────────────────────────
    # PENDING_OTP   → user must verify OTP (all risk levels)
    # PENDING_HIGH  → HIGH risk: in 10-min delay window, can be cancelled
    # SUCCESS       → LOW/MEDIUM completed normally after OTP
    # HIGH_RISK_VERIFIED → HIGH risk delay expired, transfer executed
    # SUSPICIOUS    → user cancelled during HIGH delay
    # BLOCKED       → admin confirmed as FRAUD
    # FAILED        → insufficient balance at execution time
    STATUS_CHOICES = [
        ('PENDING_OTP',        'Pending OTP Verification'),
        ('PENDING_HIGH',       'Pending – High Risk Delay'),
        ('SUCCESS',            'Success'),
        ('HIGH_RISK_VERIFIED', 'High Risk Verified & Executed'),
        ('SUSPICIOUS',         'Suspicious (Cancelled)'),
        ('BLOCKED',            'Blocked – Confirmed Fraud'),
        ('FAILED',             'Failed'),
    ]
    RISK_CHOICES = [
        ('LOW',    'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH',   'High'),
    ]
    CLASS_CHOICES = [
        ('SAFE',       'Safe'),
        ('HIGH_RISK',  'High Risk Verified'),
        ('SUSPICIOUS', 'Suspicious'),
        ('FRAUD',      'Confirmed Fraud'),
        ('PENDING',    'Pending'),
    ]

    id           = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    cancel_token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user         = models.ForeignKey(User, on_delete=models.CASCADE, related_name='transactions')

    bill_type        = models.CharField(max_length=255)
    amount           = models.DecimalField(max_digits=12, decimal_places=2)
    receiver_account = models.CharField(max_length=20, blank=True, default='')
    receiver_bank    = models.CharField(max_length=100, blank=True, default='')

    status         = models.CharField(max_length=25, choices=STATUS_CHOICES, default='PENDING_OTP')
    risk_level     = models.CharField(max_length=10, choices=RISK_CHOICES, default='LOW')
    risk_score     = models.IntegerField(default=0)
    classification = models.CharField(max_length=15, choices=CLASS_CHOICES, default='PENDING')
    explanation    = models.TextField(blank=True, default='')

    created_at    = models.DateTimeField(auto_now_add=True)
    execute_after = models.DateTimeField(null=True, blank=True)   # HIGH delay deadline
    executed_at   = models.DateTimeField(null=True, blank=True)
    cancelled_at  = models.DateTimeField(null=True, blank=True)

    otp_verified  = models.BooleanField(default=False)
    pin_verified  = models.BooleanField(default=False)

    admin_note           = models.TextField(blank=True, default='')
    admin_classified_by  = models.ForeignKey(User, null=True, blank=True,
                               on_delete=models.SET_NULL, related_name='classified_txns')

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} | {self.bill_type} | ₹{self.amount} | {self.status}"

    def delay_seconds_remaining(self):
        if self.execute_after:
            return max(0, int((self.execute_after - timezone.now()).total_seconds()))
        return 0

    def delay_expired(self):
        return bool(self.execute_after and timezone.now() >= self.execute_after)

    def get_explanation_list(self):
        return [e.strip() for e in self.explanation.split('|') if e.strip()]

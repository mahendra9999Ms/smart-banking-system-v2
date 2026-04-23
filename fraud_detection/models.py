from django.contrib.auth.models import User
from django.db import models


class FraudRecord(models.Model):
    user        = models.ForeignKey(User, on_delete=models.CASCADE)
    bill_type   = models.CharField(max_length=100)
    amount      = models.DecimalField(max_digits=12, decimal_places=2)
    risk_score  = models.IntegerField(default=0)
    risk_level  = models.CharField(max_length=10, default='LOW')
    explanation = models.TextField(blank=True, default='')
    detected_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-detected_at']

    def __str__(self):
        return f"{self.user.username} | {self.risk_level} | ₹{self.amount}"

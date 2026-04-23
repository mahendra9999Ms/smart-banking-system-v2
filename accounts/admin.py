from django.contrib import admin
from .models import UserProfile, AuditLog
admin.site.register(UserProfile)
admin.site.register(AuditLog)

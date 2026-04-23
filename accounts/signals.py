from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import UserProfile

@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    if created:
        # Staff/superusers are always ACTIVE — no approval needed
        status = 'ACTIVE' if (instance.is_staff or instance.is_superuser) else 'PENDING'
        profile, _ = UserProfile.objects.get_or_create(user=instance)
        if profile.account_status == 'PENDING' and status == 'ACTIVE':
            profile.account_status = 'ACTIVE'
            profile.save(update_fields=['account_status'])

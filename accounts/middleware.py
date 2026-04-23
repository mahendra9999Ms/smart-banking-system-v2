from django.shortcuts import redirect
from django.contrib.auth import logout

EXEMPT = ['/transactions/cancel/']

class BlockedUserMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if any(request.path.startswith(e) for e in EXEMPT):
            return self.get_response(request)
        if request.user.is_authenticated:
            # Staff and superusers are never blocked by middleware
            if not (request.user.is_staff or request.user.is_superuser):
                try:
                    p = request.user.userprofile
                    if p.account_status == 'BLOCKED' or not request.user.is_active:
                        logout(request)
                        return redirect('login')
                except Exception:
                    pass
        return self.get_response(request)

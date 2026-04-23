import hashlib, random
from datetime import timedelta
from decimal import Decimal

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib import messages
from django.db.models import Sum
from django.core.paginator import Paginator
from django.utils import timezone

from .models import UserProfile, AuditLog
from transactions.models import Transaction
from fraud_detection.models import FraudRecord

# Progressive lock: after N failures → lock for M minutes
LOCK_MAP = {3: 5, 4: 15, 5: 60}


def is_admin(u): return u.is_staff


def log_action(actor, action, target='', details=''):
    AuditLog.objects.create(actor=actor, action=action, target=target, details=details)


# ── LOGIN ──────────────────────────────────────────────────────────────
def login_view(request):
    if request.user.is_authenticated:
        return redirect('admin_dashboard' if request.user.is_staff else 'user_dashboard')

    error = None
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')

        try:
            profile = UserProfile.objects.get(user__username=username)
        except UserProfile.DoesNotExist:
            profile = None

        # Check progressive lock
        if profile and profile.is_locked():
            secs = profile.lock_seconds_remaining()
            error = f"Account locked. Try again in {secs // 60}m {secs % 60}s."
            return render(request, 'login.html', {'error': error})

        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Staff and superusers bypass all account_status checks
            if user.is_staff or user.is_superuser:
                if profile:
                    profile.failed_login_attempts = 0
                    profile.locked_until = None
                    profile.save(update_fields=['failed_login_attempts', 'locked_until'])
                login(request, user)
                return redirect('admin_dashboard')

            status = getattr(profile, 'account_status', 'ACTIVE') if profile else 'ACTIVE'
            if status == 'PENDING':
                error = "Your account is pending admin approval. Please wait."
            elif status == 'REJECTED':
                error = f"Account rejected. Reason: {profile.rejection_reason or 'Contact admin.'}"
            elif status == 'BLOCKED' or not user.is_active:
                error = "Account blocked. Contact the bank administrator."
            else:
                if profile:
                    profile.failed_login_attempts = 0
                    profile.locked_until = None
                    profile.save(update_fields=['failed_login_attempts', 'locked_until'])
                login(request, user)
                return redirect('admin_dashboard' if user.is_staff else 'user_dashboard')
        else:
            if profile:
                profile.failed_login_attempts += 1
                n = profile.failed_login_attempts
                lock_mins = LOCK_MAP.get(n, 60 if n > 5 else 0)
                if lock_mins:
                    profile.locked_until = timezone.now() + timedelta(minutes=lock_mins)
                    error = f"Wrong credentials. Locked for {lock_mins} min after {n} attempts."
                else:
                    left = 3 - n
                    error = f"Wrong credentials. {max(left,0)} attempt(s) left before lock."
                profile.save(update_fields=['failed_login_attempts', 'locked_until'])
            else:
                error = "Invalid username or password."

    return render(request, 'login.html', {'error': error})


# ── REGISTER ───────────────────────────────────────────────────────────
def register_view(request):
    if request.user.is_authenticated:
        return redirect('user_dashboard')
    msg = None
    if request.method == 'POST':
        username  = request.POST.get('username', '').strip()
        password  = request.POST.get('password', '')
        confirm   = request.POST.get('confirm_password', '')
        full_name = request.POST.get('full_name', '').strip()
        email     = request.POST.get('email', '').strip()
        phone     = request.POST.get('phone', '').strip()
        pin       = request.POST.get('pin', '').strip()

        if not username or not password:
            msg = "Username and password are required."
        elif len(password) < 6:
            msg = "Password must be at least 6 characters."
        elif password != confirm:
            msg = "Passwords do not match."
        elif pin and (not pin.isdigit() or len(pin) != 4):
            msg = "PIN must be exactly 4 digits."
        elif User.objects.filter(username=username).exists():
            msg = "Username already taken."
        else:
            user = User.objects.create_user(username=username, password=password, is_active=False)
            p = UserProfile.objects.get(user=user)
            p.full_name = full_name
            p.email = email
            p.phone = phone
            p.account_status = 'PENDING'
            if pin:
                p.set_pin(pin)
            p.save()
            messages.success(request, "Registered! Waiting for admin approval before you can login.")
            return redirect('login')
    return render(request, 'register.html', {'message': msg})


@login_required
def logout_view(request):
    logout(request)
    return redirect('login')


# ── SET PIN ─────────────────────────────────────────────────────────────
@login_required
def set_pin(request):
    """
    Change/Set transaction PIN.
    - First-time setup: no verification needed (no existing PIN).
    - Changing existing PIN: must verify via OLD PIN or OTP.
    OTP method: user requests OTP (sent to session), enters it + new PIN.
    """
    p   = UserProfile.objects.get(user=request.user)
    msg = None
    has_pin = bool(p.pin_hash)

    if request.method == 'POST':
        action = request.POST.get('action', 'set')

        # ── Step 1: Request OTP for PIN change ────────────────────────
        if action == 'request_otp':
            otp    = str(random.randint(100000, 999999))
            expiry = (timezone.now() + timedelta(minutes=5)).isoformat()
            request.session['pin_otp_hash']   = hashlib.sha256(otp.encode()).hexdigest()
            request.session['pin_otp_expiry'] = expiry
            request.session['pin_otp_plain']  = otp   # demo — show on screen
            msg = f"otp_sent:{otp}"

        # ── Step 2: Verify via OLD PIN then set new PIN ───────────────
        elif action == 'change_via_old_pin':
            old_pin  = request.POST.get('old_pin', '').strip()
            new_pin  = request.POST.get('new_pin', '').strip()
            conf_pin = request.POST.get('confirm_new_pin', '').strip()

            if not p.pin_hash:
                msg = "No existing PIN. Please use Set New PIN below."
            elif not p.check_pin(old_pin):
                msg = "error:Old PIN is incorrect."
            elif not new_pin.isdigit() or len(new_pin) != 4:
                msg = "error:New PIN must be exactly 4 digits."
            elif new_pin != conf_pin:
                msg = "error:New PINs do not match."
            elif new_pin == old_pin:
                msg = "error:New PIN must be different from old PIN."
            else:
                p.set_pin(new_pin)
                p.save(update_fields=['pin_hash'])
                log_action(request.user, "Changed PIN via Old PIN", request.user.username)
                msg = "success:PIN changed successfully."

        # ── Step 3: Verify via OTP then set new PIN ───────────────────
        elif action == 'change_via_otp':
            from django.utils.dateparse import parse_datetime
            entered_otp = request.POST.get('otp', '').strip()
            new_pin     = request.POST.get('new_pin', '').strip()
            conf_pin    = request.POST.get('confirm_new_pin', '').strip()

            otp_hash   = request.session.get('pin_otp_hash', '')
            otp_expiry = request.session.get('pin_otp_expiry', '')

            if not otp_hash:
                msg = "error:No OTP found. Please request OTP first."
            else:
                expiry_dt = parse_datetime(otp_expiry)
                if expiry_dt and timezone.now() > expiry_dt:
                    for k in ('pin_otp_hash', 'pin_otp_expiry', 'pin_otp_plain'):
                        request.session.pop(k, None)
                    msg = "error:OTP expired. Please request a new OTP."
                elif hashlib.sha256(entered_otp.encode()).hexdigest() != otp_hash:
                    msg = "error:Invalid OTP. Please try again."
                elif not new_pin.isdigit() or len(new_pin) != 4:
                    msg = "error:New PIN must be exactly 4 digits."
                elif new_pin != conf_pin:
                    msg = "error:New PINs do not match."
                else:
                    p.set_pin(new_pin)
                    p.save(update_fields=['pin_hash'])
                    for k in ('pin_otp_hash', 'pin_otp_expiry', 'pin_otp_plain'):
                        request.session.pop(k, None)
                    log_action(request.user, "Changed PIN via OTP", request.user.username)
                    msg = "success:PIN changed successfully via OTP."

        # ── First-time PIN setup (no existing PIN) ────────────────────
        elif action == 'set_new':
            new_pin  = request.POST.get('new_pin', '').strip()
            conf_pin = request.POST.get('confirm_new_pin', '').strip()

            if p.pin_hash:
                msg = "error:PIN already set. Use Change PIN option above."
            elif not new_pin.isdigit() or len(new_pin) != 4:
                msg = "error:PIN must be exactly 4 digits."
            elif new_pin != conf_pin:
                msg = "error:PINs do not match."
            else:
                p.set_pin(new_pin)
                p.save(update_fields=['pin_hash'])
                log_action(request.user, "Set PIN", request.user.username)
                msg = "success:PIN set successfully."

    otp_plain = request.session.get('pin_otp_plain', '')
    return render(request, 'user/set_pin.html', {
        'profile':   p,
        'has_pin':   has_pin,
        'msg':       msg,
        'otp_plain': otp_plain,
    })


# ── USER DASHBOARD ──────────────────────────────────────────────────────
@login_required
def user_dashboard(request):
    if request.user.is_staff:
        return redirect('admin_dashboard')
    p = UserProfile.objects.get(user=request.user)

    # Auto-expire abandoned PENDING_OTP transactions older than 10 minutes
    from transactions.models import Transaction as Txn
    stale_cutoff = timezone.now() - timedelta(minutes=10)
    Txn.objects.filter(
        user=request.user,
        status='PENDING_OTP',
        created_at__lt=stale_cutoff
    ).update(status='FAILED')

    pending_high = Txn.objects.filter(user=request.user, status='PENDING_HIGH')
    recent       = Txn.objects.filter(user=request.user).exclude(
                       status='PENDING_OTP').order_by('-created_at')[:5]
    return render(request, 'user/dashboard.html', {
        'profile': p, 'balance': p.balance,
        'account_number': p.account_number,
        'pending_high': pending_high, 'recent': recent,
    })


# ── USER PROFILE ─────────────────────────────────────────────────────────
@login_required
def profile(request):
    p = UserProfile.objects.get(user=request.user)
    msg = None
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'update_profile':
            p.full_name = request.POST.get('full_name', '').strip()
            p.email     = request.POST.get('email', '').strip()
            p.phone     = request.POST.get('phone', '').strip()
            p.save()
            msg = "success:Profile updated."
        elif action == 'change_password':
            old = request.POST.get('old_password', '')
            new = request.POST.get('new_password', '')
            cnf = request.POST.get('confirm_password', '')
            if not request.user.check_password(old):
                msg = "Current password is incorrect."
            elif new != cnf:
                msg = "New passwords do not match."
            elif len(new) < 6:
                msg = "Min 6 characters."
            else:
                request.user.set_password(new)
                request.user.save()
                update_session_auth_hash(request, request.user)
                msg = "success:Password changed."
    return render(request, 'user/profile.html', {'profile': p, 'msg': msg})


# ── ADMIN DASHBOARD ───────────────────────────────────────────────────────
@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    ctx = {
        'user_count':          User.objects.filter(is_staff=False).count(),
        'total_transactions':  Transaction.objects.count(),
        'fraud_count':         FraudRecord.objects.count(),
        'total_balance':       UserProfile.objects.aggregate(s=Sum('balance'))['s'] or 0,
        'pending_approvals':   UserProfile.objects.filter(account_status='PENDING').count(),
        'pending_high_count':  Transaction.objects.filter(status='PENDING_HIGH').count(),
        'suspicious_count':    Transaction.objects.filter(status='SUSPICIOUS').count(),
        'recent_fraud':        FraudRecord.objects.order_by('-detected_at')[:5],
        'pending_users':       UserProfile.objects.filter(account_status='PENDING').select_related('user')[:5],
    }
    return render(request, 'admin/dashboard.html', ctx)


# ── PENDING USERS ─────────────────────────────────────────────────────────
@login_required
@user_passes_test(is_admin)
def pending_users(request):
    users = UserProfile.objects.filter(account_status='PENDING').select_related('user').order_by('user__date_joined')
    return render(request, 'admin/pending_users.html', {'pending_profiles': users})


# ── APPROVE / REJECT USER ─────────────────────────────────────────────────
@login_required
@user_passes_test(is_admin)
def approve_user(request, user_id):
    p = get_object_or_404(UserProfile, user_id=user_id)
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'approve':
            bal = Decimal(request.POST.get('initial_balance', '5000'))
            p.account_status = 'ACTIVE'
            p.balance        = bal
            p.approved_by    = request.user
            p.approved_at    = timezone.now()
            p.user.is_active = True
            p.user.save()
            p.save()
            log_action(request.user, "Approve User", p.user.username, f"Balance ₹{bal}")
        elif action == 'reject':
            reason = request.POST.get('reason', '').strip()
            p.account_status    = 'REJECTED'
            p.rejection_reason  = reason
            p.save()
            log_action(request.user, "Reject User", p.user.username, reason)
    return redirect('pending_users')


# ── MANAGE USERS ──────────────────────────────────────────────────────────
@login_required
@user_passes_test(is_admin)
def manage_users(request):
    if request.method == 'POST':
        uid    = request.POST.get('user_id')
        action = request.POST.get('action')
        user   = get_object_or_404(User, id=uid)
        p      = user.userprofile

        if action == 'block':
            p.account_status = 'BLOCKED'
            user.is_active = False
            user.save()
            p.save()
            log_action(request.user, "Block User", user.username)

        elif action == 'unblock':
            p.account_status = 'ACTIVE'
            user.is_active = True
            user.save()
            p.save()
            log_action(request.user, "Unblock User", user.username)

        elif action == 'delete':
            # Safety: cannot delete staff/superusers from this panel
            if user.is_staff or user.is_superuser:
                messages.error(request, "Cannot delete admin accounts from this panel.")
                return redirect('manage_users')
            username = user.username
            user.delete()  # cascades to UserProfile via OneToOne + FraudRecord + Transaction
            log_action(request.user, "Delete User", username,
                       "User account permanently deleted.")
            messages.success(request, f"User '{username}' has been permanently deleted.")

        return redirect('manage_users')

    q  = request.GET.get('q', '').strip()
    qs = User.objects.filter(is_superuser=False).select_related('userprofile').order_by('username')
    if q:
        qs = qs.filter(
            username__icontains=q
        ) | qs.filter(
            userprofile__full_name__icontains=q
        ) | qs.filter(
            userprofile__email__icontains=q
        )
        qs = qs.distinct()
    page = Paginator(qs, 10).get_page(request.GET.get('page'))
    return render(request, 'admin/manage_users.html', {'users': page, 'q': q})


# ── CREATE USER ──────────────────────────────────────────────────────────
@login_required
@user_passes_test(is_admin)
def create_user(request):
    msg = None
    if request.method == 'POST':
        uname = request.POST['username']
        pw    = request.POST['password']
        bal   = Decimal(request.POST.get('balance', '5000'))
        if User.objects.filter(username=uname).exists():
            msg = "Username already exists!"
        else:
            u = User.objects.create_user(username=uname, password=pw, is_active=True)
            p = u.userprofile
            p.balance        = bal
            p.full_name      = request.POST.get('full_name', '')
            p.email          = request.POST.get('email', '')
            p.phone          = request.POST.get('phone', '')
            p.account_status = 'ACTIVE'
            p.approved_by    = request.user
            p.approved_at    = timezone.now()
            p.save()
            log_action(request.user, "Create Account", uname, f"₹{bal}")
            msg = "success:Account created successfully."
    return render(request, 'admin/create_user.html', {'msg': msg})


# ── EDIT USER ───────────────────────────────────────────────────────────
@login_required
@user_passes_test(is_admin)
def edit_user(request, user_id):
    tu = get_object_or_404(User, id=user_id)
    p  = tu.userprofile
    msg = None
    if request.method == 'POST':
        action = request.POST.get('action', 'update')
        if action == 'update':
            new_uname = request.POST.get('username', '').strip()
            if new_uname and new_uname != tu.username:
                if User.objects.filter(username=new_uname).exists():
                    msg = "Username already taken."
                    return render(request, 'admin/edit_user.html',
                                  {'target_user': tu, 'profile': p, 'message': msg})
                tu.username = new_uname
                tu.save()
            p.full_name = request.POST.get('full_name', '')
            p.email     = request.POST.get('email', '')
            p.phone     = request.POST.get('phone', '')
            p.save()
            log_action(request.user, "Edit User", tu.username)
            msg = "success:User updated."
        elif action == 'reset_password':
            pw  = request.POST.get('new_password', '')
            cnf = request.POST.get('confirm_password', '')
            if pw != cnf:
                msg = "Passwords do not match."
            elif len(pw) < 6:
                msg = "Min 6 characters."
            else:
                tu.set_password(pw)
                tu.save()
                log_action(request.user, "Reset Password", tu.username)
                msg = "success:Password reset."
    return render(request, 'admin/edit_user.html',
                  {'target_user': tu, 'profile': p, 'message': msg})


# ── ADJUST BALANCE ──────────────────────────────────────────────────────
@login_required
@user_passes_test(is_admin)
def adjust_balance(request, user_id):
    user = get_object_or_404(User, id=user_id)
    p    = user.userprofile
    if request.method == 'POST':
        action = request.POST.get('action')
        amount = Decimal(request.POST.get('amount', '0'))
        if action == 'credit':
            p.balance += amount
        elif action == 'debit':
            if amount > p.balance:
                return redirect('manage_users')
            p.balance -= amount
        p.save()
        Transaction.objects.create(
            user=user, bill_type="Admin Adjustment",
            amount=amount, status='SUCCESS',
            risk_level='LOW', classification='SAFE',
        )
        log_action(request.user, f"Balance {action.title()}", user.username, f"₹{amount}")
    return redirect('manage_users')


# ── AUDIT LOG ──────────────────────────────────────────────────────────
@login_required
@user_passes_test(is_admin)
def audit_log_view(request):
    qs   = AuditLog.objects.all()
    page = Paginator(qs, 20).get_page(request.GET.get('page'))
    return render(request, 'admin/audit_log.html', {'logs': page})

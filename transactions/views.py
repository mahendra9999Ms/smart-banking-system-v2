import hashlib, random
from datetime import datetime
from decimal import Decimal

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib import messages
from django.db import transaction as db_transaction
from django.core.paginator import Paginator
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from accounts.models import UserProfile
from accounts.views import log_action
from .models import Transaction
from fraud_detection.ml_model import predict_fraud, get_risk_level
from fraud_detection.models import FraudRecord

HIGH_DELAY_MINUTES = 10


# ── Helpers ─────────────────────────────────────────────────────────────
def _hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()


def _fraud_pipeline(amount, bill_type, profile, past_txns):
    """Returns (risk_score, risk_level, explanation_list)."""
    ml_risk = 60 if predict_fraud(amount, bill_type) == 1 else 10
    b_risk  = 0
    expl    = []

    if profile.average_transaction_amount > 0:
        avg = float(profile.average_transaction_amount)
        if (float(amount) - avg) / avg > 2:
            b_risk += 40
            expl.append("Amount is 3× above your usual average")

    if past_txns.exists():
        diff = (timezone.now() - past_txns.first().created_at).total_seconds()
        if diff < 60:
            b_risk += 25
            expl.append("Another transaction occurred less than 60 seconds ago")

    h = datetime.now().hour
    if not (profile.usual_transaction_hour_start <= h <= profile.usual_transaction_hour_end):
        b_risk += 15
        expl.append("Transaction is outside your usual active hours")

    score = min(ml_risk + b_risk, 95)
    return score, get_risk_level(score), expl


def _update_avg(user):
    """
    Recalculate behavioral average from ONLY LOW and MEDIUM successful transactions.

    HIGH risk transactions (status=HIGH_RISK_VERIFIED, risk_level=HIGH)
    are STRICTLY EXCLUDED — even if this function is called after one.
    This prevents fraudsters from shifting the baseline by executing
    high-value transfers and making future large transactions appear normal.
    """
    past = Transaction.objects.filter(
        user=user,
        status='SUCCESS',                      # only normally completed txns
        risk_level__in=['LOW', 'MEDIUM'],      # HIGH is explicitly excluded
    )
    if past.exists():
        p = user.userprofile
        p.average_transaction_amount = sum(t.amount for t in past) / past.count()
        p.save(update_fields=['average_transaction_amount'])


def _do_transfer(txn):
    """Debit sender, credit receiver (internal). Returns (ok, err)."""
    try:
        with db_transaction.atomic():
            sp = txn.user.userprofile
            sp.refresh_from_db()
            if txn.amount > sp.balance:
                return False, "Insufficient balance at execution time."
            sp.balance -= txn.amount
            sp.save()
            if txn.receiver_bank == 'ASB':
                try:
                    rp = UserProfile.objects.get(account_number=txn.receiver_account)
                    rp.balance += txn.amount
                    rp.save()
                    Transaction.objects.create(
                        user=rp.user,
                        bill_type=f"Received from {sp.account_number}",
                        amount=txn.amount,
                        status='SUCCESS', risk_level='LOW', classification='SAFE',
                    )
                except UserProfile.DoesNotExist:
                    pass  # external — simulated
        return True, None
    except Exception as e:
        return False, str(e)


# ── Transaction history ──────────────────────────────────────────────────
@login_required
def transaction_history(request):
    qs = Transaction.objects.filter(user=request.user)

    q    = request.GET.get('q', '').strip()
    st   = request.GET.get('status', '').strip()
    risk = request.GET.get('risk', '').strip()
    fd   = request.GET.get('from_date', '').strip()
    td   = request.GET.get('to_date', '').strip()

    if q:    qs = qs.filter(bill_type__icontains=q)
    if st:   qs = qs.filter(status=st)
    if risk: qs = qs.filter(risk_level=risk)
    if fd:   qs = qs.filter(created_at__date__gte=fd)
    if td:   qs = qs.filter(created_at__date__lte=td)

    page = Paginator(qs, 15).get_page(request.GET.get('page'))
    return render(request, 'user/transactions.html', {
        'transactions': page,
        'q': q, 'status': st, 'risk': risk, 'from_date': fd, 'to_date': td,
    })


# ── Send money ────────────────────────────────────────────────────────────
@login_required
def send_money(request):
    sp = get_object_or_404(UserProfile, user=request.user)
    if sp.account_status != 'ACTIVE':
        return render(request, 'user/send_money.html', {'error': 'Your account is not active.'})

    if request.method == 'POST':
        bank     = request.POST.get('bank_name', 'internal')
        receiver = request.POST.get('receiver', '').strip()
        try:
            amount = Decimal(request.POST.get('amount', '0'))
        except Exception:
            return render(request, 'user/send_money.html', {'error': 'Invalid amount.'})

        if amount <= 0:
            return render(request, 'user/send_money.html', {'error': 'Amount must be > 0.'})
        if amount > sp.balance:
            return render(request, 'user/send_money.html', {'error': 'Insufficient balance.'})

        btype = 'External Transfer' if bank != 'internal' else 'Transfer'
        past  = Transaction.objects.filter(
            user=request.user,
            status__in=['SUCCESS', 'HIGH_RISK_VERIFIED']  # include both for velocity check
        ).order_by('-created_at')

        score, level, expl = _fraud_pipeline(amount, btype, sp, past)

        # Log FraudRecord only for MEDIUM and HIGH risk (not every LOW transaction)
        if level in ('MEDIUM', 'HIGH'):
            FraudRecord.objects.create(
                user=request.user, bill_type=btype, amount=amount,
                risk_score=score, risk_level=level,
                explanation=' | '.join(expl) if expl else '',
            )

        # Validate receiver early for internal
        receiver_profile = None
        if bank == 'internal':
            try:
                receiver_profile = UserProfile.objects.get(account_number=receiver)
            except UserProfile.DoesNotExist:
                return render(request, 'user/send_money.html',
                              {'error': 'Receiver account not found.'})

        # Create pending transaction
        txn = Transaction.objects.create(
            user=request.user, bill_type=btype, amount=amount,
            receiver_account=receiver,
            receiver_bank='ASB' if bank == 'internal' else bank,
            status='PENDING_OTP', risk_level=level, risk_score=score,
            classification='PENDING',
            explanation=' | '.join(expl) if expl else '',
        )

        # OTP
        otp    = str(random.randint(100000, 999999))
        expiry = (timezone.now() + timezone.timedelta(minutes=5)).isoformat()
        request.session['otp_hash']   = _hash_otp(otp)
        request.session['otp_expiry'] = expiry
        request.session['otp_plain']  = otp
        request.session['txn_id']     = str(txn.id)

        return redirect('verify_otp')

    return render(request, 'user/send_money.html', {'profile': sp})


# ── Verify OTP ────────────────────────────────────────────────────────────
@login_required
def verify_otp(request):
    txn_id = request.session.get('txn_id')
    if not txn_id:
        return redirect('send_money')
    txn = get_object_or_404(Transaction, id=txn_id, user=request.user)

    if request.method == 'POST':
        entered   = request.POST.get('otp', '').strip()
        otp_hash  = request.session.get('otp_hash', '')
        otp_expiry= request.session.get('otp_expiry', '')
        otp_plain = request.session.get('otp_plain', '')

        expiry_dt = parse_datetime(otp_expiry)
        if expiry_dt and timezone.now() > expiry_dt:
            txn.status = 'FAILED'; txn.save()
            _clear_session(request)
            return render(request, 'user/verify_otp.html',
                          {'error': 'OTP expired. Please start again.', 'txn': txn})

        if _hash_otp(entered) != otp_hash:
            return render(request, 'user/verify_otp.html',
                          {'error': 'Wrong OTP. Try again.',
                           'otp': otp_plain, 'txn': txn})

        txn.otp_verified = True
        txn.save()

        # ── Route by risk level ──────────────────────────────────────
        if txn.risk_level in ('LOW', 'MEDIUM'):
            ok, err = _do_transfer(txn)
            if ok:
                txn.status         = 'SUCCESS'
                txn.executed_at    = timezone.now()
                txn.classification = 'SAFE'
                txn.save()
                _clear_session(request)
                _update_avg(request.user)
                return render(request, 'user/receipt.html', {
                    'txn': txn,
                    'warn': txn.risk_level == 'MEDIUM',
                    'expl': txn.get_explanation_list(),
                })
            else:
                txn.status = 'FAILED'; txn.save()
                return render(request, 'user/send_money.html', {'error': err})

        # HIGH → step-up auth
        _clear_session(request)
        return redirect('step_up_auth', txn_id=txn.id)

    return render(request, 'user/verify_otp.html', {
        'otp': request.session.get('otp_plain'), 'txn': txn,
    })


# ── Step-up auth (HIGH risk PIN) ─────────────────────────────────────────
@login_required
def step_up_auth(request, txn_id):
    txn = get_object_or_404(Transaction, id=txn_id, user=request.user)
    sp  = request.user.userprofile

    if txn.status not in ('PENDING_OTP', 'PENDING_HIGH'):
        return redirect('transactions')

    if request.method == 'POST':
        pin = request.POST.get('pin', '').strip()

        if not sp.pin_hash:
            return render(request, 'user/step_up_auth.html', {
                'txn': txn, 'no_pin': True,
                'error': 'No PIN set. Set your PIN in profile first.',
            })

        if not sp.check_pin(pin):
            return render(request, 'user/step_up_auth.html', {
                'txn': txn, 'error': 'Incorrect PIN.',
            })

        # PIN OK → delay window
        txn.pin_verified  = True
        txn.status        = 'PENDING_HIGH'
        txn.execute_after = timezone.now() + timezone.timedelta(minutes=HIGH_DELAY_MINUTES)
        txn.save()

        return render(request, 'user/high_risk_pending.html', {
            'txn': txn,
            'delay_min': HIGH_DELAY_MINUTES,
            'cancel_url': request.build_absolute_uri(f'/transactions/cancel/{txn.cancel_token}/'),
        })

    return render(request, 'user/step_up_auth.html', {
        'txn': txn, 'has_pin': bool(sp.pin_hash),
    })


# ── Cancel (public URL — usable from email link) ─────────────────────────
def cancel_transaction(request, cancel_token):
    txn = get_object_or_404(Transaction, cancel_token=cancel_token)
    if txn.status != 'PENDING_HIGH':
        return render(request, 'user/cancel_result.html', {
            'txn': txn, 'ok': False,
            'msg': 'This transaction has already been processed or cannot be cancelled.',
        })
    txn.status         = 'SUSPICIOUS'
    txn.cancelled_at   = timezone.now()
    txn.classification = 'SUSPICIOUS'
    txn.admin_note     = 'Cancelled by user during HIGH-risk delay window.'
    txn.save()
    return render(request, 'user/cancel_result.html', {
        'txn': txn, 'ok': True,
        'msg': 'Transaction cancelled and marked as suspicious.',
    })


# ── Execute expired HIGH-risk transactions ──────────────────────────────
@login_required
def execute_pending(request):
    executed = []
    for txn in Transaction.objects.filter(user=request.user, status='PENDING_HIGH'):
        if txn.delay_expired():
            ok, err = _do_transfer(txn)
            if ok:
                txn.status         = 'HIGH_RISK_VERIFIED'
                txn.executed_at    = timezone.now()
                txn.classification = 'HIGH_RISK'
                txn.save()
                # ✅ DO NOT call _update_avg here.
                # HIGH risk transactions must NEVER influence the behavioral average.
                # Average is only updated from LOW and MEDIUM successful transactions.
                executed.append(txn)
            else:
                txn.status = 'FAILED'
                txn.save()

    still_pending = Transaction.objects.filter(user=request.user, status='PENDING_HIGH')
    return render(request, 'user/pending_high_list.html', {
        'executed': executed,
        'pending':  still_pending,
    })


def _clear_session(request):
    for k in ('otp_hash', 'otp_expiry', 'otp_plain', 'txn_id'):
        request.session.pop(k, None)


# ── Receive money ─────────────────────────────────────────────────────────
@login_required
# ── Transaction detail ───────────────────────────────────────────────────────
@login_required
def transaction_detail(request, txn_id):
    txn = get_object_or_404(Transaction, id=txn_id, user=request.user)
    return render(request, 'user/transaction_detail.html', {
        'txn': txn, 'expl': txn.get_explanation_list(),
    })


def receive_money(request):
    p = request.user.userprofile
    return render(request, 'user/receive_money.html', {'profile': p})


# ── Admin: all transactions ───────────────────────────────────────────────
@login_required
@user_passes_test(lambda u: u.is_staff)
def all_transactions(request):
    qs   = Transaction.objects.all()
    st   = request.GET.get('status', '')
    risk = request.GET.get('risk', '')
    if st:   qs = qs.filter(status=st)
    if risk: qs = qs.filter(risk_level=risk)
    page = Paginator(qs, 20).get_page(request.GET.get('page'))
    return render(request, 'admin/all_transactions.html', {
        'transactions': page, 'status': st, 'risk': risk,
        'status_choices': Transaction.STATUS_CHOICES,
    })


# ── Admin: classify transaction ───────────────────────────────────────────
@login_required
@user_passes_test(lambda u: u.is_staff)
def classify_transaction(request, txn_id):
    txn = get_object_or_404(Transaction, id=txn_id)
    if request.method == 'POST':
        cls  = request.POST.get('classification')
        note = request.POST.get('note', '')
        if cls in ('SAFE', 'HIGH_RISK', 'SUSPICIOUS', 'FRAUD'):
            txn.classification       = cls
            txn.admin_note           = note
            txn.admin_classified_by  = request.user
            if cls == 'FRAUD':
                txn.status = 'BLOCKED'
            txn.save()
            log_action(request.user, "Classify Transaction", str(txn.id)[:8], cls)
    return redirect('all_transactions')


# ── Admin: reports ────────────────────────────────────────────────────────
@login_required
@user_passes_test(lambda u: u.is_staff)
def reports(request):
    from django.db.models import Count
    total   = Transaction.objects.count()
    blocked = Transaction.objects.filter(status='BLOCKED').count()
    susp    = Transaction.objects.filter(status='SUSPICIOUS').count()
    hrisk   = Transaction.objects.filter(risk_level='HIGH').count()
    rate    = round(blocked / total * 100, 2) if total else 0

    monthly = (
        Transaction.objects
        .extra(select={'month': "strftime('%%m', created_at)"})
        .values('month', 'risk_level')
        .annotate(c=Count('id'))
        .order_by('month')
    )
    return render(request, 'admin/reports.html', {
        'total': total, 'blocked': blocked, 'suspicious': susp,
        'high_risk': hrisk, 'fraud_rate': rate, 'monthly': list(monthly),
    })

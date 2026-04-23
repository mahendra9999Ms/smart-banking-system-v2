from decimal import Decimal
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.db import transaction as db_transaction
from django.utils import timezone

from accounts.models import UserProfile
from transactions.models import Transaction
from transactions.views import _fraud_pipeline, _update_avg
from fraud_detection.models import FraudRecord


@login_required
def bill_pay(request):
    sp  = get_object_or_404(UserProfile, user=request.user)
    ctx = {'balance': sp.balance}

    if request.method == 'POST':
        btype = request.POST.get('bill_type', 'Electricity')
        try:
            amount = Decimal(request.POST.get('amount', '0'))
        except Exception:
            ctx['error'] = 'Invalid amount.'
            return render(request, 'user/bill_pay.html', ctx)

        if amount <= 0:
            ctx['error'] = 'Amount must be > 0.'
            return render(request, 'user/bill_pay.html', ctx)
        if amount > sp.balance:
            ctx['error'] = 'Insufficient balance.'
            return render(request, 'user/bill_pay.html', ctx)

        past  = Transaction.objects.filter(
            user=request.user,
            status__in=['SUCCESS', 'HIGH_RISK_VERIFIED']  # include both for velocity check
        ).order_by('-created_at')
        score, level, expl = _fraud_pipeline(amount, btype, sp, past)

        # Log FraudRecord only for MEDIUM and HIGH risk
        if level in ('MEDIUM', 'HIGH'):
            FraudRecord.objects.create(
                user=request.user, bill_type=btype, amount=amount,
                risk_score=score, risk_level=level,
                explanation=' | '.join(expl) if expl else '',
            )

        if level == 'HIGH':
            Transaction.objects.create(
                user=request.user, bill_type=btype, amount=amount,
                status='SUSPICIOUS', risk_level=level, risk_score=score,
                classification='SUSPICIOUS',
                explanation=' | '.join(expl),
            )
            ctx.update({'fraud': True, 'risk_level': level, 'expl': expl,
                        'msg': '⚠ High-risk payment flagged. Not processed.'})
        else:
            with db_transaction.atomic():
                sp.balance -= amount
                sp.save()
                Transaction.objects.create(
                    user=request.user, bill_type=btype, amount=amount,
                    status='SUCCESS', risk_level=level, risk_score=score,
                    classification='SAFE',
                    explanation=' | '.join(expl) if expl else '',
                )
            _update_avg(request.user)  # safe: only reached when level != HIGH
            warn = level == 'MEDIUM'
            ctx.update({'balance': sp.balance, 'expl': expl, 'risk_level': level,
                        'msg': f"{'⚠ Medium risk — ' if warn else ''}₹{amount} {btype} bill paid.",
                        'warn': warn})

    return render(request, 'user/bill_pay.html', ctx)

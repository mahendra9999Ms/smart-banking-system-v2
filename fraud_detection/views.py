from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator
from .models import FraudRecord


@login_required
@user_passes_test(lambda u: u.is_staff)
def fraud_alerts(request):
    return render(request, 'admin/fraud_alerts.html',
                  {'records': FraudRecord.objects.order_by('-detected_at')[:10]})


@login_required
@user_passes_test(lambda u: u.is_staff)
def fraud_history(request):
    qs   = FraudRecord.objects.all()
    risk = request.GET.get('risk', '')
    if risk: qs = qs.filter(risk_level=risk)
    page = Paginator(qs, 20).get_page(request.GET.get('page'))
    return render(request, 'admin/fraud_history.html', {'records': page, 'risk': risk})

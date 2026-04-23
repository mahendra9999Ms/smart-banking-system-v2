from django.urls import path
from . import views

urlpatterns = [
    path('transactions/',                                views.transaction_history, name='transactions'),
    path('send-money/',                                  views.send_money,          name='send_money'),
    path('receive-money/',                               views.receive_money,       name='receive_money'),
    path('verify-otp/',                                  views.verify_otp,          name='verify_otp'),
    path('step-up/<uuid:txn_id>/',                       views.step_up_auth,        name='step_up_auth'),
    path('transactions/cancel/<uuid:cancel_token>/',     views.cancel_transaction,  name='cancel_transaction'),
    path('transactions/execute-pending/',                views.execute_pending,     name='execute_pending'),
    path('transactions/<uuid:txn_id>/',                  views.transaction_detail,        name='transaction_detail'),
    path('control/transactions/',                        views.all_transactions,    name='all_transactions'),
    path('control/transactions/classify/<uuid:txn_id>/', views.classify_transaction,name='classify_transaction'),
    path('control/reports/',                             views.reports,             name='reports'),
]

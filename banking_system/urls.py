from django.contrib import admin
from django.urls import path, include
from accounts.views import login_view, logout_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('', include('accounts.urls')),
    path('', include('transactions.urls')),
    path('', include('billpay.urls')),
    path('', include('fraud_detection.urls')),
]

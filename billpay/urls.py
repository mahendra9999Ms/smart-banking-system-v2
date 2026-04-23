from django.urls import path
from . import views
urlpatterns = [path('bill-pay/', views.bill_pay, name='bill_pay')]

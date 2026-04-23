from django.urls import path
from . import views

urlpatterns = [
    path('register/',                              views.register_view,  name='register'),
    path('set-pin/',                               views.set_pin,        name='set_pin'),
    path('user/dashboard/',                        views.user_dashboard, name='user_dashboard'),
    path('profile/',                               views.profile,        name='profile'),
    path('control/dashboard/',                     views.admin_dashboard,name='admin_dashboard'),
    path('control/users/',                         views.manage_users,   name='manage_users'),
    path('control/users/pending/',                 views.pending_users,  name='pending_users'),
    path('control/users/approve/<int:user_id>/',   views.approve_user,   name='approve_user'),
    path('control/create-user/',                   views.create_user,    name='create_user'),
    path('control/edit-user/<int:user_id>/',       views.edit_user,      name='edit_user'),
    path('control/adjust-balance/<int:user_id>/',  views.adjust_balance, name='adjust_balance'),
    path('control/audit-log/',                     views.audit_log_view, name='audit_log'),
]

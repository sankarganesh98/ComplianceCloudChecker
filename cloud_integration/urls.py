from django.contrib import admin
from django.urls import path
from django.contrib.auth.views import LogoutView
from monitoring_app import views

urlpatterns = [
    path('checks/<int:scan_id>/', views.check_list, name='check_list'),
    path('get_remediation_guidance/', views.get_remediation_guidance, name='get_remediation_guidance'),
    path('compliance_query/', views.compliance_query, name='compliance_query'),
    path("admin/", admin.site.urls),
    path("", views.home, name="home"),  # The root URL handles the home view
    path("login/", views.login_view, name="login"),
    path("logout/", LogoutView.as_view(next_page="/login/"), name="logout"),
    path("run_scan/<int:scan_config_id>/", views.run_scan, name="run_scan"),
    path("check_list/<int:scan_id>/", views.check_list, name="check_list"),
    path("manage_compliances/", views.manage_compliances, name="manage_compliances"),
    path("edit_compliance/<int:compliance_id>/", views.edit_compliance, name="edit_compliance"),
    path("delete_compliance/<int:compliance_id>/", views.delete_compliance, name="delete_compliance"),
    path("delete_account/<int:account_id>/", views.delete_account, name="delete_account"),  # Delete account URL
    path("remove_compliance/<int:account_id>/<int:compliance_id>/", views.remove_compliance, name="remove_compliance"),  # Remove compliance URL
    path('get_available_compliances/<int:account_id>/', views.get_available_compliances, name='get_available_compliances'),
    path('add_compliance/', views.add_compliance, name='add_compliance'),
    path('create_account/', views.create_account, name='create_account'),
    path('account/<int:account_id>/report/', views.account_report_view, name='account_report'),
     path('check_connection/', views.check_connection, name='check_connection'),


]

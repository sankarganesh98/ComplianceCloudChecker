from django.contrib import admin
from .models import CloudProvider, ScanConfiguration

# Register your models here.
admin.site.register(CloudProvider)
admin.site.register(ScanConfiguration)

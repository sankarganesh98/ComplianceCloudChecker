from django.db import models



class CloudProvider(models.Model):
    PROVIDER_CHOICES = [
        ("aws", "AWS"),
        ("gcp", "GCP"),
        ("azure", "AZURE"),
    ]
    name = models.CharField(max_length=100, choices=PROVIDER_CHOICES, unique=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.get_name_display()


class ProwlerCheck(models.Model):
    check_id = models.CharField(max_length=255, unique=True)
    description = models.TextField()
    provider = models.ForeignKey(
        CloudProvider, on_delete=models.CASCADE, related_name="checks"
    )
    service = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.check_id} ({self.provider})"


class Compliance(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name


class ComplianceControl(models.Model):
    compliance = models.ForeignKey(
        Compliance, on_delete=models.CASCADE, related_name="controls"
    )
    control = models.CharField(max_length=100)
    description = models.TextField()
    checks = models.ManyToManyField(ProwlerCheck, related_name="compliance_controls")

    def __str__(self):
        return f"{self.compliance.name} - {self.control}"


class ScanConfiguration(models.Model):
    provider = models.ForeignKey(CloudProvider, on_delete=models.CASCADE)
    account_name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    config_details = models.JSONField()
    compliances = models.ManyToManyField(
        Compliance, related_name="scan_configurations", blank=True
    )

    def __str__(self):
        return f"{self.account_name} - {self.provider.name}"


class Scan(models.Model):
    scan_configuration = models.ForeignKey(
        ScanConfiguration, on_delete=models.CASCADE, related_name="scans"
    )
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    status = models.CharField(
        max_length=20,
        default="pending",
        choices=[
            ("pending", "Pending"),
            ("running", "Running"),
            ("completed", "Completed"),
            ("failed", "Failed"),
        ],
    )

    class Meta:
        indexes = [
            models.Index(fields=["start_time"]),
            models.Index(fields=["status"]),
        ]

    def __str__(self):
        return (
            f"Scan {self.id}: {self.status} - {self.scan_configuration.provider.name}"
        )

    @property
    def provider(self):
        return self.scan_configuration.provider


class Check(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="checks")
    finding_unique_id = models.CharField(max_length=255, unique=True)
    check_id = models.CharField(max_length=255)
    check_title = models.TextField()
    check_type = models.JSONField()  # Storing list of check types as JSON
    service_name = models.CharField(max_length=255, blank=True, null=True)
    sub_service_name = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=50)
    status_extended = models.TextField(blank=True, null=True)
    severity = models.CharField(max_length=50, blank=True, null=True)
    resource_type = models.CharField(max_length=100, blank=True, null=True)
    resource_details = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    risk = models.TextField(blank=True, null=True)
    related_url = models.URLField(blank=True, null=True)
    remediation = models.JSONField(
        blank=True, null=True
    )  # Nested JSON for code and recommendation
    categories = models.JSONField(blank=True, null=True)  # Optional categories
    depends_on = models.JSONField(blank=True, null=True)  # Optional dependencies
    related_to = models.JSONField(blank=True, null=True)  # Optional related checks
    notes = models.TextField(blank=True, null=True)
    profile = models.TextField(blank=True, null=True)  # Optional profile information
    account_id = models.CharField(max_length=50)
    organizations_info = models.JSONField(
        blank=True, null=True
    )  # Optional organization info
    region = models.CharField(max_length=50, blank=True, null=True)
    resource_id = models.CharField(max_length=255, blank=True, null=True)
    resource_arn = models.CharField(max_length=255, blank=True, null=True)
    resource_tags = models.JSONField(blank=True, null=True)
    first_detected = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    compliances = models.ManyToManyField(
        ComplianceControl, through="CheckControlMapping"
    )

    class Meta:
        indexes = [
            models.Index(fields=["status"], name="status_idx"),
        ]


class CheckControlMapping(models.Model):
    check_instance = models.ForeignKey(Check, on_delete=models.CASCADE)
    compliance_control = models.ForeignKey(ComplianceControl, on_delete=models.CASCADE)
    status = models.CharField(max_length=50)

    class Meta:
        unique_together = ("check_instance", "compliance_control")



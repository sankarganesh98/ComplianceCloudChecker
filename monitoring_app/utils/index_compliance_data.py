# populate_compliances.py

import os
import django

# Set up Django environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cloud_integration.settings")
django.setup()

from monitoring_app.models import Compliance, ComplianceControl, ProwlerCheck

# Define your compliance and check mappings
compliance_data = [
    {
        "compliance": "ISO_27001",
        "control": "8.13",
        "description": "Backup Configuration",
        "checks": [
            {"check_id": "backup_plans_exist", "description": "Backup Configuration"},
            {
                "check_id": "backup_reportplans_exist",
                "description": "Backup Configuration",
            },
            {
                "check_id": "backup_vaults_encrypted",
                "description": "Backup Configuration",
            },
            {"check_id": "backup_vaults_exist", "description": "Backup Configuration"},
            {"check_id": "drs_job_exist", "description": "Backup Configuration"},
            {
                "check_id": "dlm_ebs_snapshot_lifecycle_policy_exists",
                "description": "Backup Configuration",
            },
            {
                "check_id": "efs_have_backup_enabled",
                "description": "Backup Configuration",
            },
            {
                "check_id": "redshift_cluster_automated_snapshot",
                "description": "Backup Configuration",
            },
        ],
    },
    {
        "compliance": "ISO_27001",
        "control": "8.10",
        "description": "Data Retention Configuration",
        "checks": [
            {
                "check_id": "cloudwatch_log_group_retention_policy_specific_days_enabled",
                "description": "Data Retention Configuration",
            },
            {
                "check_id": "rds_instance_backup_enabled",
                "description": "Data Retention Configuration",
            },
        ],
    },
    {
        "compliance": "ISO_27001",
        "control": "8.15",
        "description": "Logging and Monitoring",
        "checks": [
            {
                "check_id": "cloudtrail_cloudwatch_logging_enabled",
                "description": "Logging and Monitoring",
            },
            {
                "check_id": "cloudfront_distributions_logging_enabled",
                "description": "Logging and Monitoring",
            },
            {
                "check_id": "guardduty_is_enabled",
                "description": "Logging and Monitoring",
            },
            {
                "check_id": "guardduty_no_high_severity_findings",
                "description": "Logging and Monitoring",
            },
            {
                "check_id": "cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled",
                "description": "Logging and Monitoring",
            },
        ],
    },
    {
        "compliance": "ISO_27001",
        "control": "8.16",
        "description": "Alerts Notifying unusual activity",
        "checks": [
            {
                "check_id": "guardduty_is_enabled",
                "description": "Alerts Notifying unusual activity",
            },
            {
                "check_id": "guardduty_no_high_severity_findings",
                "description": "Alerts Notifying unusual activity",
            },
            {
                "check_id": "cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled",
                "description": "Alerts Notifying unusual activity",
            },
        ],
    },
    {
        "compliance": "ISO_27001",
        "control": "8.24",
        "description": "Encryption Configuration for Web Services",
        "checks": [
            {
                "check_id": "acm_certificates_expiration_check",
                "description": "Encryption Configuration for Web Services",
            },
            {
                "check_id": "acm_certificates_transparency_logs_enabled",
                "description": "Encryption Configuration for Web Services",
            },
            {
                "check_id": "cloudfront_distributions_field_level_encryption_enabled",
                "description": "Encryption Configuration for Web Services",
            },
            {
                "check_id": "s3_bucket_kms_encryption",
                "description": "Encryption Configuration for Web Services",
            },
            {
                "check_id": "efs_encryption_at_rest_enabled",
                "description": "Encryption Configuration for Web Services",
            },
        ],
    },
    {
        "compliance": "ISO_27001",
        "control": "8.5",
        "description": "Configuration Settings such as Password Policies, MFA, Biometric Authentication",
        "checks": [
            {
                "check_id": "iam_password_policy_expires_passwords_within_90_days_or_less",
                "description": "Configuration Settings such as Password Policies, MFA, Biometric Authentication",
            },
            {
                "check_id": "iam_user_mfa_enabled_console_access",
                "description": "Configuration Settings such as Password Policies, MFA, Biometric Authentication",
            },
        ],
    },
    {
        "compliance": "ISO_27001",
        "control": "8.4",
        "description": "Access Control Configuration",
        "checks": [
            {
                "check_id": "iam_role_administratoraccess_policy",
                "description": "Access Control Configuration",
            },
            {
                "check_id": "apigateway_restapi_authorizers_enabled",
                "description": "Access Control Configuration",
            },
            {
                "check_id": "apigatewayv2_api_authorizers_enabled",
                "description": "Access Control Configuration",
            },
        ],
    },
    {
        "compliance": "ISO_27001",
        "control": "8.23",
        "description": "Web Application Firewall Configuration",
        "checks": [
            {
                "check_id": "cloudfront_distributions_using_waf",
                "description": "Web Application Firewall Configuration",
            },
            {
                "check_id": "wafv2_webacl_logging_enabled",
                "description": "Web Application Firewall Configuration",
            },
            {
                "check_id": "elbv2_waf_acl_attached",
                "description": "Web Application Firewall Configuration",
            },
        ],
    },
    {
        "compliance": "SOC_2",
        "control": "CC1.4",
        "description": "Segregation of Development Environments",
        "checks": [
            {
                "check_id": "glue_development_endpoints_cloudwatch_logs_encryption_enabled",
                "description": "Segregation of Development Environments",
            },
            {
                "check_id": "glue_development_endpoints_job_bookmark_encryption_enabled",
                "description": "Segregation of Development Environments",
            },
        ],
    },
    {
        "compliance": "SOC_2",
        "control": "CC1.5",
        "description": "Access Control Configuration for Staging",
        "checks": [
            {
                "check_id": "iam_role_administratoraccess_policy",
                "description": "Access Control Configuration for Staging",
            },
            {
                "check_id": "apigateway_restapi_authorizers_enabled",
                "description": "Access Control Configuration for Staging",
            },
            {
                "check_id": "iam_policy_attached_only_to_group_or_roles",
                "description": "Access Control Configuration for Staging",
            },
        ],
    },
    {
        "compliance": "SOC_2",
        "control": "CC8.1",
        "description": "Backup Configuration in Production System",
        "checks": [
            {
                "check_id": "backup_plans_exist",
                "description": "Backup Configuration in Production System",
            },
            {
                "check_id": "backup_vaults_encrypted",
                "description": "Backup Configuration in Production System",
            },
            {
                "check_id": "dlm_ebs_snapshot_lifecycle_policy_exists",
                "description": "Backup Configuration in Production System",
            },
            {
                "check_id": "backup_vaults_exist",
                "description": "Backup Configuration in Production System",
            },
        ],
    },
    {
        "compliance": "SOC_2",
        "control": "CC2.2",
        "description": "Capacity Monitoring for Storage and Processing",
        "checks": [
            {
                "check_id": "cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled",
                "description": "Capacity Monitoring for Storage and Processing",
            },
            {
                "check_id": "cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled",
                "description": "Capacity Monitoring for Storage and Processing",
            },
        ],
    },
    {
        "compliance": "SOC_2",
        "control": "A1.1",
        "description": "Automatic Backup Configuration",
        "checks": [
            {
                "check_id": "backup_vaults_encrypted",
                "description": "Automatic Backup Configuration",
            },
            {
                "check_id": "dlm_ebs_snapshot_lifecycle_policy_exists",
                "description": "Automatic Backup Configuration",
            },
            {
                "check_id": "cloudwatch_log_group_retention_policy_specific_days_enabled",
                "description": "Backup Retention Period",
            },
            {
                "check_id": "s3_bucket_kms_encryption",
                "description": "Encryption Configuration for Production",
            },
            {
                "check_id": "efs_encryption_at_rest_enabled",
                "description": "Encryption Configuration for Production",
            },
            {
                "check_id": "rds_instance_storage_encrypted",
                "description": "Encryption Configuration for Production",
            },
            {
                "check_id": "redshift_cluster_audit_logging",
                "description": "Encryption Configuration for Production",
            },
        ],
    },
]


# Insert the compliance and check data into the database
def main():
    for compliance in compliance_data:
        compliance_obj, created = Compliance.objects.get_or_create(
            name=compliance["compliance"],
            defaults={"description": compliance["compliance"]},
        )
        compliance_control, created = ComplianceControl.objects.get_or_create(
            compliance=compliance_obj,
            control=compliance["control"],
            defaults={"description": compliance["description"]},
        )
        for check in compliance["checks"]:
            prowler_check, created = ProwlerCheck.objects.get_or_create(
                check_id=check["check_id"],
                defaults={"description": check["description"]},
            )
            compliance_control.checks.add(prowler_check)
    print("Compliances and checks have been populated successfully.")


if __name__ == "__main__":
    main()

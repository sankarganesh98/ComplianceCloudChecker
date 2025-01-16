import os
import re
import subprocess
import django

# Set up Django environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cloud_integration.settings")
django.setup()

from monitoring_app.models import ProwlerCheck, CloudProvider


def run_prowler_list_checks(provider):
    if provider == "aws":
        command = ["prowler", "aws", "--list-checks"]
    elif provider == "gcp":
        command = ["prowler", "gcp", "--list-checks"]
    elif provider == "azure":
        command = ["prowler", "azure", "--list-checks"]
    else:
        raise ValueError(f"Unsupported provider: {provider}")

    result = subprocess.run(command, capture_output=True, text=True, check=True)
    return result.stdout


def remove_ansi_escape_sequences(text):
    ansi_escape = re.compile(r"\x1b\[([0-9;]*[a-zA-Z])")
    return ansi_escape.sub("", text)


def parse_and_store_checks(provider, checks_output):
    # Remove ANSI escape sequences
    clean_output = remove_ansi_escape_sequences(checks_output)
    check_pattern = re.compile(r"\[(.*?)\] (.*?) - (.*?) \[(.*?)\]")
    check_pattern = re.compile(r"\[(.*?)\] (.*?) - (.*?) \[(.*?)\]")
    provider_instance, created = CloudProvider.objects.get_or_create(name=provider)

    matches = check_pattern.findall(clean_output)

    for match in matches:
        check_id, description, service = match[0], match[1], match[2]
        prowler_check, created = ProwlerCheck.objects.get_or_create(
            check_id=check_id,
            defaults={
                "provider": provider_instance,
                "description": description,
                "service": service,
            },
        )

        if not created:
            # Update the existing prowler check if any fields have changed
            updated = False
            if prowler_check.description != description:
                prowler_check.description = description
                updated = True
            if prowler_check.service != service:
                prowler_check.service = service
                updated = True
            if updated:
                prowler_check.save()
                print(f"Updated check: {check_id} for provider: {provider}")
            else:
                print(f"No changes for check: {check_id} for provider: {provider}")
        else:
            print(f"Created new check: {check_id} for provider: {provider}")


def main():
    providers = ["aws", "gcp", "azure"]
    for provider in providers:
        print(f"Listing checks for provider: {provider}")
        checks_output = run_prowler_list_checks(provider)
        parse_and_store_checks(provider, checks_output)


if __name__ == "__main__":
    main()

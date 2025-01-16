import subprocess
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.utils import timezone
from django.http import JsonResponse
import openai
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from cryptography.fernet import Fernet
import base64

from .models import (
    Check,
    CheckControlMapping,
    Compliance,
    ComplianceControl,
    Scan,
    ScanConfiguration,
    CloudProvider,
    ProwlerCheck,
)
import os
import logging
import tempfile
import json
from collections import defaultdict
from django.contrib import messages

openai.api_key = settings.OPENAI_API_KEY

## Set up logging
logger = logging.getLogger(__name__)

def encrypt_data(data: dict) -> str:
    fernet = Fernet(settings.ENCRYPTION_KEY)
    json_data = json.dumps(data).encode()
    encrypted_data = fernet.encrypt(json_data)
    return base64.urlsafe_b64encode(encrypted_data).decode()

def decrypt_data(encrypted_data: str) -> dict:
    fernet = Fernet(settings.ENCRYPTION_KEY)
    decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
    decrypted_data = fernet.decrypt(decoded_data)
    return json.loads(decrypted_data.decode())

@login_required(login_url="/login/")
def home(request):
    if request.method == "POST":
        action = request.POST.get("action")
        
        if action == "add_compliance":
            compliance_id = request.POST.get("compliance")
            cloud_account_id = request.POST.get("cloud_account_id")

            try:
                cloud_account = get_object_or_404(ScanConfiguration, pk=cloud_account_id)
                compliance = get_object_or_404(Compliance, pk=compliance_id)

                cloud_account.compliances.add(compliance)
                cloud_account.save()

                return JsonResponse({
                    'status': 'success',
                    'compliance_id': compliance.id,
                    'compliance_name': compliance.name,
                    'compliance_description': compliance.description
                }, status=200)
            except Exception as e:
                logger.error(f"Error adding compliance: {e}")
                return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
        
        elif action == "delete_compliance":
            compliance_id = request.POST.get("compliance_id")
            cloud_account_id = request.POST.get("cloud_account_id")

            try:
                cloud_account = get_object_or_404(ScanConfiguration, pk=cloud_account_id)
                compliance = get_object_or_404(Compliance, pk=compliance_id)

                cloud_account.compliances.remove(compliance)
                
                return JsonResponse({'status': 'success'}, status=200)
            except Exception as e:
                logger.error(f"Error deleting compliance: {e}")
                return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
        
        elif action == "delete_account":
            account_id = request.POST.get("account_id")

            try:
                account = get_object_or_404(ScanConfiguration, pk=account_id)
                account.delete()
                return JsonResponse({'status': 'success'}, status=200)
            except Exception as e:
                logger.error(f"Error deleting account: {e}")
                return JsonResponse({'status': 'error', 'message': str(e)}, status=400)


    # Handle GET requests or other logic for rendering the page
    cloud_accounts = ScanConfiguration.objects.all().order_by("-id")
    cloud_accounts_with_scan_status = []
    available_compliances = Compliance.objects.all()

    for cloud_account in cloud_accounts:
        has_scan = Scan.objects.filter(scan_configuration=cloud_account).exists()
        scan_id = None
        if has_scan:
            scan = Scan.objects.get(scan_configuration=cloud_account)
            scan_id = scan.id
        
        mapped_compliances = cloud_account.compliances.all()
        remaining_compliances = available_compliances.exclude(id__in=mapped_compliances)

        cloud_accounts_with_scan_status.append(
            {
                "account_name": cloud_account.account_name,
                "provider": cloud_account.provider,
                "description": cloud_account.description,
                "has_scan": has_scan,
                "scan_id": scan_id,
                "id": cloud_account.id,
                "compliances": mapped_compliances,
                "available_compliances": remaining_compliances,
            }
        )
    
    providers = CloudProvider.objects.all()

    return render(
        request, "home.html", {
            "cloud_accounts": cloud_accounts_with_scan_status,
            "providers": providers,
            "available_compliances": available_compliances
        }
    )


def login_view(request):
    if request.user.is_authenticated:
        return redirect("home")

    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect("home")
    else:
        form = AuthenticationForm()

    return render(request, "login.html", {"form": form})

@login_required(login_url="/login/")
def check_list(request, scan_id):
    scan = get_object_or_404(Scan, pk=scan_id)

    # Get all checks related to the scan
    check_list = Check.objects.filter(scan_id=scan_id).order_by("check_id", "-status")

    # Ensure unique checks, prioritizing failed checks if duplicates exist
    unique_checks = {}
    for check in check_list:
        if check.check_id not in unique_checks or (unique_checks[check.check_id].status == 'pass' and check.status == 'fail'):
            unique_checks[check.check_id] = check

    # Extract compliances and controls from the unique checks
    displayed_compliances = set()
    displayed_controls = set()

    for check in unique_checks.values():
        for compliance_control in check.compliances.all():
            displayed_compliances.add(compliance_control.compliance)
            displayed_controls.add(compliance_control)

    # Convert to list and sort for rendering in the template
    displayed_compliances = sorted(displayed_compliances, key=lambda x: x.name)
    displayed_controls = sorted(displayed_controls, key=lambda x: x.control)

    # Insert "None" option
    displayed_compliances.insert(0, {'id': '', 'name': 'None'})
    displayed_controls.insert(0, {'id': '', 'control': 'None', 'description': ''})

    return render(request, "check_list.html", {
        "check_list": unique_checks.values(),
        "scan": scan,
        "displayed_compliances": displayed_compliances,
        "displayed_controls": displayed_controls,
        "account_id": scan.scan_configuration.id,
    })

def prepare_check_data(finding_data, scan):
    check_data = {
        "finding_unique_id": finding_data.get("FindingUniqueId"),
        "check_id": finding_data.get("CheckID"),
        "check_title": finding_data.get("CheckTitle"),
        "check_type": finding_data.get("CheckType", []),
        "service_name": finding_data.get("ServiceName", ""),
        "sub_service_name": finding_data.get("SubServiceName", ""),
        "status": finding_data.get("Status"),
        "status_extended": finding_data.get("StatusExtended", ""),
        "severity": finding_data.get("Severity", ""),
        "resource_type": finding_data.get("ResourceType", ""),
        "resource_details": finding_data.get("ResourceDetails", {}),
        "description": finding_data.get("Description", ""),
        "risk": finding_data.get("Risk", ""),
        "related_url": finding_data.get("RelatedUrl", ""),
        "remediation": finding_data.get("Remediation", {}),
        "categories": finding_data.get("Categories", []),
        "depends_on": finding_data.get("DependsOn", []),
        "related_to": finding_data.get("RelatedTo", []),
        "notes": finding_data.get("Notes", ""),
        "profile": finding_data.get("Profile", ""),
        "account_id": finding_data.get("AccountId") or finding_data.get("ProjectId")or finding_data.get("Tenant_Domain"),  # Handle missing account_id
        "organizations_info": finding_data.get("OrganizationsInfo", {}),
        "region": finding_data.get("Region"),
        "resource_id": finding_data.get("ResourceId"),
        "resource_arn": finding_data.get("ResourceArn"),
        "resource_tags": finding_data.get("ResourceTags", {}),
        "scan": scan,
    }
    return check_data

def get_checks_for_compliance_controls(compliance_controls, provider):
    checks = set()
    for control in compliance_controls:
        checks.update(
            control.checks.filter(provider__name=provider).values_list(
                "check_id", flat=True
            )
        )
    return list(checks)

def generate_scan_report(scan_id):
    scan = Scan.objects.get(id=scan_id)
    checks = Check.objects.filter(scan=scan)

    findings = [
        f"Check ID: {check.check_id}\nTitle: {check.check_title}\nStatus: {check.status}\n" 
        for check in checks
    ]
    report_content = "\n".join(findings)

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a cloud compliance report generator."},
            {"role": "user", "content": f"Generate a summary report based on the following findings:\n{report_content}"},
        ]
    )
    
    return response['choices'][0]['message']['content']

def process_prowler_output(output_json, scan, compliance_controls):
    try:
        logging.info("Processing Prowler output")
        existing_scans = Scan.objects.filter(
            scan_configuration=scan.scan_configuration
        ).exclude(id=scan.id)
        existing_scans.delete()

        processed_findings = []
        new_checks = []

        for finding_data in output_json:
            finding_unique_id = finding_data.get("FindingUniqueId")
            if finding_unique_id not in processed_findings:
                check_data = prepare_check_data(finding_data, scan)
                check = Check(**check_data)
                check.save()  # Save the check before appending to the list
                new_checks.append(check)
                processed_findings.append(finding_unique_id)
                # print(f"Check saved: ID={check.id}, CheckID={check.check_id}, Title={check.check_title}, Status={check.status}")

        check_control_mappings = []
        for check in new_checks:
            check_compliances = compliance_controls.filter(
                checks__check_id=check.check_id
            )
            for compliance_control in check_compliances:
                check_control_mappings.append(
                    CheckControlMapping(
                        check_instance=check,
                        compliance_control=compliance_control,
                        status=check.status,
                    )
                )
        CheckControlMapping.objects.bulk_create(check_control_mappings)

        # Generate report after processing
        report = generate_scan_report(scan.id)
        scan.report_content = report  # Assuming you have a report_content field in your Scan model
        scan.save()

    except Exception as e:
        logging.error(f"Error indexing Prowler output: {e}")

@login_required(login_url="/login/")
def run_scan(request, scan_config_id):
    config = ScanConfiguration.objects.get(pk=scan_config_id)
    provider = config.provider.name
    config_details = config.config_details  # Decrypted here
    scan = None
    json_file_path = None  # Define the variable at the start to ensure it's always in scope

    if provider == "aws":
        os.environ["AWS_ACCESS_KEY_ID"] = config_details["access_key_id"]
        os.environ["AWS_SECRET_ACCESS_KEY"] = config_details["secret_access_key"]
        logging.info("Environment variables for AWS set")
        prowler_command = ["prowler", "aws", "-M", "json"]

    elif provider == "gcp":
        # Extract service account key from config_details and write to a temp file
        service_account_key = config_details["service_account"]
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_file:
            temp_file.write(json.dumps(service_account_key).encode())
            temp_file_path = temp_file.name
        logging.info(f"Service account key written to temp file: {temp_file_path}")
        # print(temp_file_path)
        prowler_command = [
            "prowler",
            "gcp",
            "--credentials-file",
            temp_file_path,
            "-M",
            "json",
        ]

    elif provider == "azure":
        os.environ["AZURE_CLIENT_ID"] = config_details["client_id"]
        os.environ["AZURE_TENANT_ID"] = config_details["tenant_id"]
        os.environ["AZURE_CLIENT_SECRET"] = config_details["client_secret"]
        # Print each environment variable to verify it has been set
        # print("AZURE_CLIENT_ID:", os.environ["AZURE_CLIENT_ID"])
        # print("AZURE_TENANT_ID:", os.environ["AZURE_TENANT_ID"])
        # print("AZURE_CLIENT_SECRET:", os.environ["AZURE_CLIENT_SECRET"])
        logging.info("Environment variables for Azure set")
        prowler_command = ["prowler", "azure", "--sp-env-auth", "-M", "json"]
    try:
        compliance_from_env = os.environ.get("COMPLIANCE")

        if compliance_from_env:
            logging.info(f"Using compliance from environment: {compliance_from_env}")
            compliances = Compliance.objects.filter(name=compliance_from_env)
        else:
            logging.info("Using compliance from scan configuration")
            compliances = config.compliances.all()

        compliance_controls = ComplianceControl.objects.filter(
            compliance__in=compliances
        )

        checks_to_run = get_checks_for_compliance_controls(
            compliance_controls, provider
        )

        prowler_command.extend(["--checks"] + checks_to_run)
        logging.info(
            f"Initiating Prowler scan with command: {' '.join(prowler_command)}"
        )

        process = subprocess.run(
            prowler_command, capture_output=True, text=True, check=False
        )

        prowler_output_lines = process.stdout.splitlines()
        # print(prowler_output_lines)

        json_file_path = None
        for line in prowler_output_lines:
            if "JSON:" in line:
                json_file_path = line.split("JSON:")[1].strip()
                logging.info(f"JSON file path found: {json_file_path}")

        if json_file_path:
            with open(json_file_path, "r") as json_file:
                output_json = json.load(json_file)
                scan = Scan(scan_configuration=config, status="completed")
                scan.save()
                process_prowler_output(output_json, scan, compliance_controls)

        else:
            logging.warning("JSON file path not found in Prowler output")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error running Prowler: {e}")
    except Exception as ex:
        logging.error(f"Error processing Prowler output: {ex}")
    finally:
        if provider == "aws":
            del os.environ["AWS_ACCESS_KEY_ID"]
            del os.environ["AWS_SECRET_ACCESS_KEY"]

        elif provider == "azure":
            del os.environ["AZURE_CLIENT_ID"]
            del os.environ["AZURE_TENANT_ID"]
            del os.environ["AZURE_CLIENT_SECRET"]

        if json_file_path:
            os.remove(json_file_path)
        # Save the end_time
        if scan:
            scan.end_time = timezone.now()
            scan.save()
        logging.info("Clearing environment variables and scan output file")
    return redirect("home")

@login_required(login_url="/login/")
def manage_compliances(request):
    compliances = Compliance.objects.all().order_by("name")
    providers = CloudProvider.objects.all()
    checks = ProwlerCheck.objects.all().order_by("provider", "service")

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "create_compliance":
            name = request.POST.get("name")
            description = request.POST.get("description")
            new_compliance = Compliance.objects.create(name=name, description=description)
            return redirect('edit_compliance', compliance_id=new_compliance.id)

    return render(request, 'manage_compliances.html', {
        'compliances': compliances,
        'providers': providers,
        'checks': checks
    })

@login_required(login_url="/login/")
def edit_compliance(request, compliance_id=None):
    if compliance_id and compliance_id != 0:
        compliance = get_object_or_404(Compliance, pk=compliance_id)
    else:
        compliance = None

    aws_provider = CloudProvider.objects.get(name="aws")
    gcp_provider = CloudProvider.objects.get(name="gcp")
    azure_provider = CloudProvider.objects.get(name="azure")

    aws_checks = ProwlerCheck.objects.filter(provider=aws_provider)
    gcp_checks = ProwlerCheck.objects.filter(provider=gcp_provider)
    azure_checks = ProwlerCheck.objects.filter(provider=azure_provider)

    if request.method == "POST":
        if compliance is None:
            compliance = Compliance.objects.create(
                name=request.POST.get("name"),
                description=request.POST.get("description"),
            )
        else:
            compliance.name = request.POST.get("name")
            compliance.description = request.POST.get("description")
            compliance.save()

        # Existing controls before processing the form data
        existing_controls = {control.id: control for control in compliance.controls.all()}

        controls_data = request.POST.items()
        processed_control_ids = set()

        for key, value in controls_data:
            if key.startswith("controls") and "[name]" in key:
                control_id = key.split('[')[1].split(']')[0]
                control_name = value
                control_description = request.POST.get(f'controls[{control_id}][description]')
                
                if control_id.isdigit() and int(control_id) in existing_controls:
                    control = existing_controls[int(control_id)]
                    control.control = control_name
                    control.description = control_description
                    control.save()
                    processed_control_ids.add(int(control_id))
                else:
                    control = ComplianceControl.objects.create(
                        compliance=compliance,
                        control=control_name,
                        description=control_description
                    )
                    processed_control_ids.add(control.id)

                control.checks.clear()

                # Add selected AWS, GCP, and Azure checks
                aws_checks_selected = request.POST.getlist(f'controls[{control_id}][aws_checks][]')
                gcp_checks_selected = request.POST.getlist(f'controls[{control_id}][gcp_checks][]')
                azure_checks_selected = request.POST.getlist(f'controls[{control_id}][azure_checks][]')

                for check_id in aws_checks_selected:
                    check = ProwlerCheck.objects.get(pk=check_id)
                    control.checks.add(check)

                for check_id in gcp_checks_selected:
                    check = ProwlerCheck.objects.get(pk=check_id)
                    control.checks.add(check)

                for check_id in azure_checks_selected:
                    check = ProwlerCheck.objects.get(pk=check_id)
                    control.checks.add(check)

        # Remove controls that were not included in the processed controls
        for control_id in existing_controls.keys():
            if control_id not in processed_control_ids:
                existing_controls[control_id].delete()

        return redirect('manage_compliances')

    return render(request, 'edit_compliance.html', {
        'compliance': compliance,
        'aws_checks': aws_checks,
        'gcp_checks': gcp_checks,
        'azure_checks': azure_checks,
    })

@login_required(login_url="/login/")
def delete_compliance(request, compliance_id):
    compliance = get_object_or_404(Compliance, pk=compliance_id)

    if request.method == 'POST':
        compliance.delete()
        return JsonResponse({'status': 'success'}, status=200)
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)
    
@login_required(login_url="/login/")
def delete_account(request, account_id):
    account = get_object_or_404(ScanConfiguration, pk=account_id)

    if request.method == 'POST':
        account.delete()
        return JsonResponse({'status': 'success'}, status=200)
    elif request.method == 'GET':
        account.delete()
        return redirect('home')
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)
    
@login_required(login_url="/login/")
def remove_compliance(request, account_id, compliance_id):
    cloud_account = get_object_or_404(ScanConfiguration, pk=account_id)
    compliance = get_object_or_404(Compliance, pk=compliance_id)

    if request.method == 'GET':
        cloud_account.compliances.remove(compliance)
        return redirect('home')
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

@login_required(login_url="/login/")
def get_available_compliances(request, account_id):
    cloud_account = get_object_or_404(ScanConfiguration, pk=account_id)
    all_compliances = Compliance.objects.all()
    added_compliances = cloud_account.compliances.all()
    available_compliances = all_compliances.difference(added_compliances)

    available_compliances_data = [
        {"id": compliance.id, "name": compliance.name}
    for compliance in available_compliances]

    return JsonResponse({"available_compliances": available_compliances_data})

@login_required(login_url="/login/")
def add_compliance(request):
    if request.method == "POST":
        cloud_account_id = request.POST.get("cloud_account_id")
        compliance_id = request.POST.get("compliance")
        
        try:
            cloud_account = get_object_or_404(ScanConfiguration, pk=cloud_account_id)
            compliance = get_object_or_404(Compliance, pk=compliance_id)
            cloud_account.compliances.add(compliance)
            cloud_account.save()
            messages.success(request, f'Compliance "{compliance.name}" added successfully.')
        except Exception as e:
            messages.error(request, f"Error adding compliance: {str(e)}")

    return redirect("home")


@login_required(login_url="/login/")
def create_account(request):
    if request.method == "POST":
        # Debugging: Print the received data
        print("Provider ID:", request.POST.get("provider"))
        print("Account Name:", request.POST.get("account_name"))
        print("Description:", request.POST.get("description"))
        print("Compliances:", request.POST.getlist("compliances[]"))
        print("Connection String:", request.POST.get("connection_string"))

        provider_id = request.POST.get("provider")
        account_name = request.POST.get("account_name")
        description = request.POST.get("description")
        connection_string = request.POST.get("connection_string")
        compliances = request.POST.getlist("compliances[]")

        try:
            # Check if the received values are correct before proceeding
            provider = get_object_or_404(CloudProvider, pk=provider_id)
            connection_data = json.loads(connection_string)  # Parse the connection string into a dictionary

            # Validate JSON structure based on the provider
            if provider.name.lower() == "aws":
                print("aws came")
                if not all(key in connection_data for key in ["access_key_id", "secret_access_key"]):
                    raise ValueError("Invalid AWS configuration: missing 'access_key_id' or 'secret_access_key'")
            elif provider.name.lower() == "gcp":
                if "service_account" not in connection_data:
                    raise ValueError("Invalid GCP configuration: missing 'service_account' key")
            elif provider.name.lower() == "azure":
                if not all(key in connection_data for key in ["client_id", "tenant_id", "client_secret"]):
                    raise ValueError("Invalid Azure configuration: missing 'client_id', 'tenant_id', or 'client_secret'")

            # Create the account configuration
            account = ScanConfiguration.objects.create(
                provider=provider,
                account_name=account_name,
                description=description,
                config_details=connection_data  # This will be encrypted
            )
            print("account created")


            # Add the selected compliances to the account
            for compliance_id in compliances:
                print(f"Adding compliance: {compliance_id}")
                compliance = get_object_or_404(Compliance, pk=compliance_id)
                account.compliances.add(compliance)
            
            account.save()
            messages.success(request, "Account created successfully.")
            print("all ok")
            return JsonResponse({'success': True})

        except json.JSONDecodeError:
            messages.error(request, "Invalid JSON format in connection string.")
            return redirect('create_account')

        except ValueError as ve:
            messages.error(request, str(ve))
            return redirect('create_account')

        except Exception as e:
            messages.error(request, f"Error creating account: {str(e)}")
            return redirect('create_account')

    else:
        providers = CloudProvider.objects.all()
        available_compliances = Compliance.objects.all()
        aws_provider_id = CloudProvider.objects.get(name__iexact="aws").id
        gcp_provider_id = CloudProvider.objects.get(name__iexact="gcp").id
        azure_provider_id = CloudProvider.objects.get(name__iexact="azure").id
        print("all created")

        return render(request, "create_account.html", {
            "providers": providers,
            "available_compliances": available_compliances,
            "aws_provider_id": aws_provider_id,
            "gcp_provider_id": gcp_provider_id,
            "azure_provider_id": azure_provider_id,
        })

    
# OpenAI Integration Section
@csrf_exempt
def compliance_query(request):
    if request.method == 'POST':
        user_query = request.POST.get('query', '')

        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cloud compliance expert."},
                    {"role": "user", "content": user_query},
                ]
            )
            answer = response['choices'][0]['message']['content']
            return JsonResponse({'answer': answer}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request'}, status=400)

@csrf_exempt
def get_remediation_guidance(request):
    if request.method == 'POST':
        check_id = request.POST.get('check_id')

        # Fetch check details using check_id
        check = get_object_or_404(Check, id=check_id)
        
        # Generate the prompt for ChatGPT
        user_query = f"Provide remediation steps for the following check:\nTitle: {check.check_title}\nDescription: {check.description}\nStatus: {check.status}\nSeverity: {check.severity}"

        try:
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a cloud security expert providing remediation guidance."},
                    {"role": "user", "content": user_query},
                ]
            )
            guidance = response['choices'][0]['message']['content']
            return JsonResponse({'guidance': guidance}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request'}, status=400)

def generate_account_report(account_id):
    # Fetch all scans related to the account
    scans = Scan.objects.filter(scan_configuration__id=account_id)

    # Initialize variables to calculate overall scan score and collect findings
    total_checks = 0
    passed_checks = 0
    failed_checks = 0
    critical_issues = []
    major_issues = []
    minor_issues = []
    
    # Process each scan and its checks
    for scan in scans:
        checks = Check.objects.filter(scan=scan)
        for check in checks:
            total_checks += 1
            if check.status.lower() == 'pass':
                passed_checks += 1
            else:
                failed_checks += 1
                # Categorize the issue based on severity
                if check.severity.lower() == 'high':
                    critical_issues.append(check)
                elif check.severity.lower() == 'medium':
                    major_issues.append(check)
                else:
                    minor_issues.append(check)

    # Calculate the scan score (e.g., percentage of passed checks)
    scan_score = (passed_checks / total_checks) * 100 if total_checks > 0 else 0

    prompt = f"""
    Generate a detailed cloud compliance report for Account ID {account_id}. The report should be structured with the following sections:

    1. Introduction:
       - Provide an overview of the security checks conducted on the cloud resources associated with this account.
       - Mention the purpose of the report: to evaluate the security posture, identify potential risks, and suggest steps for compliance improvement.

    2. Scan Score:
       - The overall security score for the account is {scan_score:.2f}%. Explain how this score is calculated based on the number of security checks passed versus the total number of checks performed.
       - Describe what a higher score indicates in terms of security posture.

    3. Finding Summaries:
       - Critical Issues: Summarize the critical issues found. Include the issue title, affected service, region, description, and recommended remediation. These issues should be prioritized for immediate action.
       - Major Issues: Summarize the major issues found. Include the issue title, affected service, region, description, and recommended remediation. These issues pose significant risks and should be addressed promptly.
       - Minor Issues: Summarize the minor issues found. Include the issue title, affected service, region, description, and recommended remediation. These issues are low in severity but should still be monitored and resolved as part of regular security maintenance.

       Critical Issues:
       {"; ".join([f"{check.check_title} in {check.service_name} ({check.region}). Description: {check.description}. Remediation: {check.remediation.get('Recommendation', {}).get('Text', 'No specific remediation provided.')}" for check in critical_issues])}
       
       Major Issues:
       {"; ".join([f"{check.check_title} in {check.service_name} ({check.region}). Description: {check.description}. Remediation: {check.remediation.get('Recommendation', {}).get('Text', 'No specific remediation provided.')}" for check in major_issues])}
       
       Minor Issues:
       {"; ".join([f"{check.check_title} in {check.service_name} ({check.region}). Description: {check.description}. Remediation: {check.remediation.get('Recommendation', {}).get('Text', 'No specific remediation provided.')}" for check in minor_issues])}

    4. Immediate Action Needs:
       - Recommend actions based on the findings, with a focus on the critical issues first, followed by major and minor issues.

    5. Roadmap to Compliance:
       - Suggest a structured approach to achieve full compliance. Include immediate remediation steps, ongoing monitoring practices, adoption of security best practices, regular audits, and training for personnel.

    6. Conclusion:
       - Summarize the importance of addressing the identified issues and following the recommended roadmap to improve compliance and reduce security risks.

    End the report with a clear call to action for addressing the critical and major issues immediately.
    """

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a cloud security expert."},
            {"role": "user", "content": prompt},
        ]
    )

    report_content = response['choices'][0]['message']['content']
    return report_content

def account_report_view(request, account_id):
    report_content = generate_account_report(account_id)
    return render(request, 'account_report.html', {
        'account_id': account_id,
        'report_content': report_content
    })

@login_required(login_url="/login/")
def check_connection(request):
    try:
        # Extract data from the request payload
        provider = request.POST.get('provider')
        config_details = json.loads(request.POST.get('config_details', '{}'))

        # Map numerical provider values to provider names
        provider_map = {
            "1": "aws",
            "2": "gcp",
            "3": "azure"
        }

        provider = provider_map.get(provider)

        if not provider or not config_details:
            return JsonResponse({'status': 'error', 'message': 'Provider and config_details are required'}, status=400)

        if provider == "aws":
            os.environ["AWS_ACCESS_KEY_ID"] = config_details["access_key_id"]
            os.environ["AWS_SECRET_ACCESS_KEY"] = config_details["secret_access_key"]
            command = ["aws", "s3", "ls"]
            result = subprocess.run(command, capture_output=True, text=True)

        elif provider == "gcp":
            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_file:
                temp_file.write(json.dumps(config_details["service_account"]).encode())
                temp_file_path = temp_file.name
            
            auth_command = [
                "gcloud",
                "auth",
                "activate-service-account",
                "--key-file",
                temp_file_path
            ]
            auth_result = subprocess.run(auth_command, capture_output=True, text=True)

            if auth_result.returncode != 0:
                logger.error(f"GCP authentication failed: {auth_result.stderr}")
                os.remove(temp_file_path)
                return JsonResponse({'status': 'error', 'message': f"GCP authentication failed: {auth_result.stderr}"}, status=400)

            list_command = [
                "gcloud",
                "projects",
                "list",
                "--format=json"
            ]
            result = subprocess.run(list_command, capture_output=True, text=True)
            os.remove(temp_file_path)

        elif provider == "azure":
            auth_command = [
                "az", "login",
                "--service-principal",
                "--username", config_details["client_id"],
                "--password", config_details["client_secret"],
                "--tenant", config_details["tenant_id"]
            ]
            auth_result = subprocess.run(auth_command, capture_output=True, text=True)

            if auth_result.returncode != 0:
                logger.error(f"Azure authentication failed: {auth_result.stderr}")
                return JsonResponse({'status': 'error', 'message': f"Azure authentication failed: {auth_result.stderr}"}, status=400)

            command = ["az", "account", "list", "--output", "json"]
            result = subprocess.run(command, capture_output=True, text=True)

        else:
            return JsonResponse({'status': 'error', 'message': 'Unsupported provider'}, status=400)

        if result.returncode == 0:
            messages.success(request, "Connection successful!")
            return JsonResponse({'status': 'success', 'output': result.stdout}, status=200)
        else:
            logger.error(f"Connection failed: {result.stderr}")
            return JsonResponse({'status': 'error', 'message': result.stderr}, status=400)

    except Exception as e:
        logger.error(f"Error checking connection: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

    finally:
        if provider == "aws":
            os.environ.pop("AWS_ACCESS_KEY_ID", None)
            os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
        elif provider == "azure":
            os.environ.pop("AZURE_CLIENT_ID", None)
            os.environ.pop("AZURE_TENANT_ID", None)
            os.environ.pop("AZURE_CLIENT_SECRET", None)

<h1>3C Application (Cloud Compliance & Configuration)</h1>

<h2>Overview</h2>
<p>The 3C Application is an AI-driven tool designed to enhance cloud security management and compliance verification across multi-cloud environments. It supports internal auditors and security professionals by automating security configuration checks, providing real-time remediation recommendations, and enhancing the speed and accuracy of threat detection and response for major cloud platforms including AWS, Azure, and GCP.</p>

<h2>Key Features</h2>
<ul>
    <li><strong>Compliance Framework Customization:</strong> Allows users to create tailored compliance frameworks to meet organizational needs.</li>
    <li><strong>Automated Compliance Checks:</strong> Supports the automation of compliance validation and continuous monitoring.</li>
    <li><strong>Real-Time AI Assistance:</strong> Leverages OpenAI's advanced algorithms for real-time remediation recommendations.</li>
    <li><strong>Multi-Cloud Support:</strong> Manages cloud accounts and performs security checks across multiple providers like AWS, Google Cloud, and Azure.</li>
    <li><strong>Enhanced Reporting:</strong> Generates comprehensive summary reports that provide prioritized insights and a strategic remediation roadmap.</li>
</ul>

<h2>Prerequisites</h2>
<p>Ensure you have the following before beginning installation:</p>
<ul>
    <li>Python 3.8 or higher</li>
    <li>pip (Python package installer)</li>
    <li>Virtual environment (recommended)</li>
</ul>

<h2>Setup Instructions</h2>
<ol>
    <li><strong>Clone the Repository</strong>
        <pre>git clone https://github.com/sankarganesh98/ComplianceCloudChecker.git
cd ComplianceCloudChecker</pre>
    </li>
    <li><strong>Set Up a Virtual Environment</strong> (Optional but recommended)
        <pre>python -m venv env
source env/bin/activate  # On Windows use `env\Scripts\activate`</pre>
    </li>
    <li><strong>Install Required Packages</strong>
        <pre>pip install -r requirements.txt</pre>
    </li>
    <li><strong>Set Environment Variables</strong>
        <p>Create a <code>.env</code> file in the project directory and add the following variables:</p>
        <pre>DJANGO_SECRET_KEY='your_secret_django_key_here'
OPENAI_API_KEY='your_openai_api_key_here'</pre>
        <p>Replace 'your_secret_django_key_here' and 'your_openai_api_key_here' with your actual keys.</p>
    </li>
    <li><strong>Initialize the Database</strong>
        <pre>python manage.py migrate</pre>
    </li>
    <li><strong>Run the Development Server</strong>
        <pre>python manage.py runserver</pre>
        <p>Access the application at <a href="http://localhost:8000">http://localhost:8000</a>.</p>
    </li>
</ol>

<h2>Application Pages</h2>
<h3>1. Login Page</h3>
<p>Secure user authentication page for access control.</p>
<img src="https://github.com/user-attachments/assets/19d0710e-bc1b-40ef-bcc7-54188e286e75" alt="Login Page" width="1470" />

<h3>2. Dashboard</h3>
<p>Control center displaying compliance status and quick access to features.</p>
<img src="https://github.com/user-attachments/assets/4b161e53-e2cd-4b22-9f55-7dfeb79d4840" alt="Dashboard" width="1470" />

<h3>4. Cloud Accounts Management</h3>
<p>Configure and manage integration with AWS, Azure, and GCP.</p>
<img src="https://github.com/user-attachments/assets/39330027-1a8d-4727-b448-7f34a2ae63b9" alt="Cloud Accounts Management" width="1470" />

<h3>5. Compliance Checks Setup</h3>
<p>Set up and initiate compliance checks across your cloud platforms.</p>
<img src="https://github.com/user-attachments/assets/0a1986c4-956c-473d-add8-973508a56c69" alt="Compliance Checks Setup" width="1470" />

<h3>6. Findings Management</h3>
<p>View and manage findings from compliance checks.</p>
<img src="https://github.com/user-attachments/assets/0a1986c4-956c-473d-add8-973508a56c69" alt="Findings Management" width="1470" />

<h3>8. AI Query Section</h3>
<p>Interact with an AI interface for real-time compliance and security guidance.</p>
<img src="https://github.com/user-attachments/assets/b5050426-b40e-44f2-9a67-82207905b795" alt="AI Query Section" width="1470" />

<h3>9. Reports and Analytics</h3>
<p>Access comprehensive reports and analytics on cloud compliance.</p>
<img src="https://github.com/user-attachments/assets/e908b196-f9ed-42a6-86e9-fe1320b34630" alt="Reports and Analytics" width="1470" />

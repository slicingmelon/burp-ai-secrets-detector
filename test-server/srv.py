from flask import Flask, jsonify, render_template_string
import random
import string
import os

app = Flask(__name__)


def generate_aws_key():
    # Use fixed prefix that matches the regex
    prefix = "AKIA"
    # Generate random character suffix (20 chars total - prefix length)
    suffix_length = 20 - len(prefix)
    suffix = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(suffix_length))
    return prefix + suffix

def generate_api_key():
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

def generate_github_token():
    return 'ghp_' + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(36))

def create_secrets_js():
    with open('static/secrets.js', 'w') as f:
        f.write(f'''// Configuration file
const API_SETTINGS = {{
    timeout: 30000,
    retries: 3,
    github_token: "{generate_github_token()}"
}};
''')

# Ensure static directory exists
os.makedirs('static', exist_ok=True)
create_secrets_js()

@app.route('/1')
def endpoint_one():
    api_key = generate_api_key()
    api_key_2 = generate_api_key()
    api_key_3 = generate_api_key()
    
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secret in JavaScript</title>
    </head>
    <body>
        <h1>Page with Secret in JavaScript</h1>
        <p>This page contains a secret API key in a script tag.</p>
        
        <script>
            // Initialize API configuration
            const config = {{
                apiKey: "{api_key}",
                endpoint: "https://api.example.com",
                timeout: 5000
            }};
            
            // JSON string format
            const jsonData = `{{"secret":"{api_key_2}"}}`;
            
            // Escaped JSON format
            const escapedJson = "\\"apiKey\\":\\"{api_key_3}\\"";
            
            // Full URL with secret
            const fullURL = "https://site.com/api.php?secret={api_key}&token={api_key_2}&page=1";
            
            console.log("API initialized with configuration");
        </script>
        
        <div style="margin-top: 50px; padding: 20px; background-color: #f0f0f0; border: 1px solid #ccc;">
            <h3>Total Secrets: 5</h3>
            <p>This endpoint contains 5 secrets that should be detected:
            <ul>
                <li>1 API key in JavaScript config object</li>
                <li>1 API key in JSON string</li>
                <li>1 API key in escaped JSON</li>
                <li>2 API keys in URL query parameters</li>
            </ul>
            </p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html_content)

@app.route('/2-aws')
def endpoint_two():
    aws_key = generate_aws_key()
    aws_key_2 = generate_aws_key()
    aws_key_3 = generate_aws_key()
    
    return jsonify({
        "status": "success",
        "data": {
            "user": "testuser",
            "aws_access_key": aws_key,
            "region": "us-west-2"
        },
        "config": {
            "json_data": f'{{"aws_secret":"{aws_key_2}"}}',
            "escaped_json": f'\\"aws_key\\":\\"{aws_key_3}\\"',
            "full_url": f"https://aws.amazon.com/console?access_key={aws_key}&secret={aws_key_2}&region=us-east-1"
        },
        "total_secrets": 5,
        "secret_breakdown": {
            "aws_keys_in_json": 3,
            "aws_keys_in_url": 2
        }
    })

@app.route('/3-github')
def endpoint_three():
    github_token = generate_github_token()
    github_token_2 = generate_github_token()
    github_token_3 = generate_github_token()
    
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>GitHub Token Example</title>
        <script src="/static/secrets.js"></script>
    </head>
    <body>
        <h1>Page with GitHub Token</h1>
        <p>This page loads a local secrets.js file and also contains a GitHub token in the code below:</p>
        
        <pre>
        function authenticateWithGitHub() {{
            // Sample code showing token usage
            const headers = {{
                'Authorization': 'token {github_token}'
            }};
            
            fetch('https://api.github.com/user', {{
                method: 'GET',
                headers: headers
            }})
            .then(response => response.json())
            .then(data => console.log(data));
        }}
        </pre>
        
        <script>
            // JSON string format
            const githubConfig = `{{"github_token":"{github_token_2}"}}`;
            
            // Escaped JSON format
            const escapedGithubJson = "\\"token\\":\\"{github_token_3}\\"";
            
            // Full URL with GitHub token
            const githubURL = "https://github.com/api/user?token={github_token}&access_token={github_token_2}";
            
            console.log("GitHub tokens loaded");
        </script>
        
        <div style="margin-top: 50px; padding: 20px; background-color: #f0f0f0; border: 1px solid #ccc;">
            <h3>Total Secrets: 6</h3>
            <p>This endpoint contains 6 secrets that should be detected:
            <ul>
                <li>1 GitHub token in external secrets.js file</li>
                <li>1 GitHub token in pre tag</li>
                <li>1 GitHub token in JSON string</li>
                <li>1 GitHub token in escaped JSON</li>
                <li>2 GitHub tokens in URL query parameters</li>
            </ul>
            </p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html_content)

@app.route('/4-all')
def endpoint_four():
    # Generate all three types of secrets
    aws_key = generate_aws_key()
    api_key = generate_api_key()
    github_token = generate_github_token()
    
    # Additional secrets for new formats
    aws_key_2 = generate_aws_key()
    api_key_2 = generate_api_key()
    github_token_2 = generate_github_token()
    
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Multiple Secrets Example</title>
        <script src="/static/secrets.js"></script>
    </head>
    <body>
        <h1>Page with Multiple Secrets</h1>
        <p>This page contains multiple different types of secrets for testing detection.</p>
        
        <!-- AWS Key in HTML comment -->
        <!-- AWS Access Key: {aws_key} -->
        
        <div class="config-section">
            <h2>AWS Configuration</h2>
            <p>Region: us-east-1</p>
            <p>Access Key ID: AKIAIOSFODNN7EXAMPLE</p>
            <p>Secret Access Key: {aws_key}</p>
        </div>
        
        <script>
            // Initialize API configuration with API key
            const config = {{
                apiKey: "{api_key}",
                endpoint: "https://api.example.com",
                timeout: 5000
            }};
            
            console.log("API initialized with configuration");
            
            // GitHub token used in JavaScript function
            function authenticateWithGitHub() {{
                const headers = {{
                    'Authorization': 'token {github_token}'
                }};
                
                fetch('https://api.github.com/user', {{
                    method: 'GET',
                    headers: headers
                }})
                .then(response => response.json())
                .then(data => console.log(data));
            }}
            
            // JSON string formats
            const awsConfig = `{{"aws_access_key":"{aws_key_2}","region":"us-west-2"}}`;
            const apiConfig = `{{"api_key":"{api_key_2}","timeout":5000}}`;
            const githubConfig = `{{"github_token":"{github_token_2}"}}`;
            
            // Escaped JSON formats
            const escapedAws = "\\"aws_key\\":\\"{aws_key}\\"";
            const escapedApi = "\\"apiKey\\":\\"{api_key_2}\\"";
            const escapedGithub = "\\"github_token\\":\\"{github_token_2}\\"";
            
            // Full URLs with secrets
            const awsURL = "https://console.aws.amazon.com/s3?access_key={aws_key}&secret={aws_key_2}";
            const apiURL = "https://api.service.com/endpoint?key={api_key}&token={api_key_2}";
            const githubURL = "https://api.github.com/repos/user/repo?token={github_token}&access_token={github_token_2}";
        </script>
        
        <h3>Sample Code</h3>
        <pre>
        // Example GitHub authentication
        const githubAuth = {{
            token: "ghp_{github_token[4:]}",
            username: "testuser"
        }};
        </pre>
        
        <div style="margin-top: 50px; padding: 20px; background-color: #f0f0f0; border: 1px solid #ccc;">
            <h3>Total Secrets: 17</h3>
            <p>This endpoint contains 17 secrets that should be detected:
            <ul>
                <li>1 GitHub token in external secrets.js file</li>
                <li>2 AWS keys (1 in comment, 1 in HTML text)</li>
                <li>2 API keys in JavaScript config and variables</li>
                <li>2 GitHub tokens in JavaScript function and pre tag</li>
                <li>3 secrets in JSON strings (AWS, API, GitHub)</li>
                <li>3 secrets in escaped JSON (AWS, API, GitHub)</li>
                <li>4 secrets in URL query parameters (2 AWS, 2 API, 2 GitHub)</li>
            </ul>
            </p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html_content)

@app.route('/6-static-aws-github')
def endpoint_six_static():
    # Static, non-random secrets for consistent testing
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    github_token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
    
    # Additional static secrets
    aws_key_2 = "AKIAI44QH8DHBEXAMPLE"
    github_token_2 = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
    
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Static Secrets Example</title>
    </head>
    <body>
        <h1>Page with Static Secrets</h1>
        <p>This page contains static secrets that never change between requests.</p>
        
        <div class="config-section">
            <h2>AWS Configuration</h2>
            <p>Region: us-east-1</p>
            <p>Secret Access Key: {aws_key}</p>
        </div>
        
        <script>
            // GitHub token used in JavaScript function
            function authenticateWithGitHub() {{
                const headers = {{
                    'Authorization': 'token {github_token}'
                }};
                
                fetch('https://api.github.com/user', {{
                    method: 'GET',
                    headers: headers
                }})
                .then(response => response.json())
                .then(data => console.log(data));
            }}
            
            // JSON string formats
            const awsData = `{{"aws_access_key":"{aws_key_2}"}}`;
            const githubData = `{{"github_token":"{github_token_2}"}}`;
            
            // Escaped JSON formats
            const escapedAwsJson = "\\"aws_secret\\":\\"{aws_key}\\"";
            const escapedGithubJson = "\\"token\\":\\"{github_token_2}\\"";
            
            // Full URLs with secrets
            const awsConsoleURL = "https://console.aws.amazon.com/iam?access_key={aws_key}&secret_key={aws_key_2}";
            const githubApiURL = "https://api.github.com/user/repos?token={github_token}&access_token={github_token_2}";
        </script>
        
        <div style="margin-top: 50px; padding: 20px; background-color: #f0f0f0; border: 1px solid #ccc;">
            <h3>Total Secrets: 10</h3>
            <p>This endpoint contains 10 secrets that should be detected:
            <ul>
                <li>2 AWS keys (1 in HTML text, 1 in JavaScript function)</li>
                <li>2 GitHub tokens (1 in JavaScript function, 1 in variable)</li>
                <li>2 secrets in JSON strings (1 AWS, 1 GitHub)</li>
                <li>2 secrets in escaped JSON (1 AWS, 1 GitHub)</li>
                <li>4 secrets in URL query parameters (2 AWS, 2 GitHub)</li>
            </ul>
            </p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html_content)

@app.route('/7-fixed-patterns-aws-github-gcp')
def endpoint_seven_fixed_patterns():
    # Static secrets that match our new regex patterns exactly
    aws_key = "AKIAIOSFODNN7EXAMPL0"  # Fixed AWS format
    github_token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"  # GitHub PAT
    gcp_key = "AIzaSy1234567890abcdefghijklmnopqrstuvw"  # GCP key
    
    # Additional secrets for new formats
    aws_key_2 = "AKIAI44QH8DHBEXAMPLE"
    github_token_2 = "ghp_9876543210zyxwvutsrqponmlkjihgfedcbaZ"
    gcp_key_2 = "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Fixed Pattern Secrets Example</title>
    </head>
    <body>
        <h1>Page with Properly Formatted Secrets</h1>
        <p>This page contains secrets formatted to match our regex patterns.</p>
        
        <div class="config-section">
            <h2>AWS Configuration</h2>
            <p>Region: us-east-1</p>
            <p>AWS Access Key: {aws_key}</p>
        </div>
        
        <div class="config-section">
            <h2>GCP Configuration</h2>
            <p>GCP API Key: {gcp_key}</p>
        </div>
        
        <div class="config-section">
            <h2>GitHub Configuration</h2>
            <p>GitHub PAT: {github_token}</p>
        </div>
        
        <script>
            // JSON string formats
            const awsConfig = `{{"aws_access_key":"{aws_key_2}","region":"us-west-2"}}`;
            const gcpConfig = `{{"gcp_api_key":"{gcp_key_2}","project":"test-project"}}`;
            const githubConfig = `{{"github_token":"{github_token_2}","username":"testuser"}}`;
            
            // Escaped JSON formats
            const escapedAws = "\\"aws_key\\":\\"{aws_key}\\"";
            const escapedGcp = "\\"gcp_key\\":\\"{gcp_key_2}\\"";
            const escapedGithub = "\\"github_token\\":\\"{github_token_2}\\"";
            
            // Full URLs with secrets
            const awsURL = "https://s3.amazonaws.com/bucket?AWSAccessKeyId={aws_key}&SecretKey={aws_key_2}";
            const gcpURL = "https://googleapis.com/storage/v1/b/bucket?key={gcp_key}&api_key={gcp_key_2}";
            const githubURL = "https://api.github.com/user?token={github_token}&access_token={github_token_2}";
            
            console.log("All cloud service tokens loaded");
        </script>
        
        <div style="margin-top: 50px; padding: 20px; background-color: #f0f0f0; border: 1px solid #ccc;">
            <h3>Total Secrets: 15</h3>
            <p>This endpoint contains 15 secrets that should be detected:
            <ul>
                <li>3 secrets in HTML text (1 AWS, 1 GCP, 1 GitHub)</li>
                <li>3 secrets in JSON strings (1 AWS, 1 GCP, 1 GitHub)</li>
                <li>3 secrets in escaped JSON (1 AWS, 1 GCP, 1 GitHub)</li>
                <li>6 secrets in URL query parameters (2 AWS, 2 GCP, 2 GitHub)</li>
            </ul>
            </p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html_content)

@app.route('/8-fixed-patterns-no-groups-npm')
def endpoint_eight_fixed_patterns_no_groups():
    # Static secrets that match our new regex patterns exactly
    npm_token = "npm_n3A6gZxL5PqWsCtVmRbKyDjeFHuQiTwY0921"
    npm_token_2 = "npm_X7Y8Z9A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5"
    
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Fixed Pattern Secrets Example - NPM</title>
    </head>
    <body>
        <h1>Page with Properly Formatted NPM Secrets</h1>
        <p>This page contains NPM secrets formatted to match our regex patterns.</p>
        
        <div class="config-section">
            <h2>NPM Configuration</h2>
            <p>NPM Token: {npm_token}</p>
        </div>
        
        <script>
            // JSON string format
            const npmConfig = `{{"npm_token":"{npm_token_2}","registry":"https://registry.npmjs.org"}}`;
            
            // Escaped JSON format
            const escapedNpmJson = "\\"npm_token\\":\\"{npm_token}\\"";
            
            // Full URL with NPM token
            const npmURL = "https://registry.npmjs.org/package?token={npm_token}&auth_token={npm_token_2}";
            
            console.log("NPM configuration loaded");
        </script>
        
        <div style="margin-top: 50px; padding: 20px; background-color: #f0f0f0; border: 1px solid #ccc;">
            <h3>Total Secrets: 5</h3>
            <p>This endpoint contains 5 secrets that should be detected:
            <ul>
                <li>1 NPM token in HTML text</li>
                <li>1 NPM token in JSON string</li>
                <li>1 NPM token in escaped JSON</li>
                <li>2 NPM tokens in URL query parameters</li>
            </ul>
            </p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html_content)

@app.route('/')
def index():
    """Show an index of all available endpoints"""
    endpoints = [
        {"path": "/1", "name": "API Key in JavaScript"},
        {"path": "/2-aws", "name": "AWS Access Key in JSON Response"},
        {"path": "/3-github", "name": "GitHub Token Example"},
        {"path": "/4-all", "name": "Multiple Secrets Example"},
        {"path": "/6-static-aws-github", "name": "Static AWS and GitHub Secrets"},
        {"path": "/7-fixed-patterns-aws-github-gcp", "name": "Fixed Pattern Secrets (AWS, GitHub, GCP)"},
        {"path": "/8-fixed-patterns-no-groups-npm", "name": "Fixed Pattern Secrets - No Groups (NPM)"}
    ]
    
    html_content = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secret Detection Test Server</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 20px;
                line-height: 1.6;
            }
            h1 {
                color: #333;
                border-bottom: 1px solid #ccc;
                padding-bottom: 10px;
            }
            ul {
                list-style-type: none;
                padding: 0;
            }
            li {
                margin: 10px 0;
                padding: 10px;
                background-color: #f5f5f5;
                border-radius: 4px;
            }
            a {
                color: #0066cc;
                text-decoration: none;
                font-weight: bold;
            }
            a:hover {
                text-decoration: underline;
            }
            .description {
                font-size: 0.9em;
                color: #666;
                margin-top: 5px;
            }
        </style>
    </head>
    <body>
        <h1>Secret Detection Test Server</h1>
        <p>Click on any endpoint below to generate a test response containing various secrets:</p>
        <ul>
    '''
    
    for endpoint in endpoints:
        html_content += f'''
            <li>
                <a href="{endpoint['path']}">{endpoint['path']}</a>
                <div class="description">{endpoint['name']}</div>
            </li>
        '''
    
    html_content += '''
        </ul>
    </body>
    </html>
    '''
    
    return render_template_string(html_content)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9095, debug=True)
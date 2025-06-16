from flask import Flask, jsonify, render_template_string
import random
import string
import os
import json
from datetime import datetime

app = Flask(__name__)

# Secret tracking for testing purposes
SECRET_REGISTRY = {
    "generated_at": None,
    "endpoints": {}
}

def log_secret(endpoint, secret_type, secret_value, location):
    """Log a secret and its source for testing identification"""
    if SECRET_REGISTRY["generated_at"] is None:
        SECRET_REGISTRY["generated_at"] = datetime.now().isoformat()
    
    if endpoint not in SECRET_REGISTRY["endpoints"]:
        SECRET_REGISTRY["endpoints"][endpoint] = []
    
    SECRET_REGISTRY["endpoints"][endpoint].append({
        "type": secret_type,
        "value": secret_value,
        "location": location,
        "logged_at": datetime.now().isoformat()
    })
    
    # Save to file for testing reference
    with open('static/secret_registry.json', 'w') as f:
        json.dump(SECRET_REGISTRY, f, indent=2)

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

def create_endpoint_secrets_js(endpoint_name):
    """Create a unique secrets.js file for each endpoint"""
    filename = f'static/secrets-{endpoint_name}.js'
    github_token = generate_github_token()
    
    # Log the secret for testing identification
    log_secret(endpoint_name, "github_token", github_token, f"secrets-{endpoint_name}.js")
    
    with open(filename, 'w') as f:
        f.write(f'''// Configuration file for endpoint {endpoint_name}
// SECRET_SOURCE: endpoint-{endpoint_name}
// SECRET_TYPE: github_token
const API_SETTINGS = {{
    timeout: 30000,
    retries: 3,
    github_token: "{github_token}",
    endpoint_id: "{endpoint_name}"
}};

// Pure secret for pattern matching (source: endpoint-{endpoint_name})
const ENDPOINT_SECRET = "{github_token}";
''')
    return github_token

# Ensure static directory exists
os.makedirs('static', exist_ok=True)

@app.route('/1')
def endpoint_one():
    api_key = generate_api_key()
    api_key_2 = generate_api_key()
    api_key_3 = generate_api_key()
    
    # Log all secrets for testing identification
    log_secret("ep1", "api_key", api_key, "JavaScript config")
    log_secret("ep1", "api_key", api_key_2, "JSON string")
    log_secret("ep1", "api_key", api_key_3, "Escaped JSON")
    
    # Create endpoint-specific secrets file (also logs its own secret)
    endpoint_github_token = create_endpoint_secrets_js("ep1")
    
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secret in JavaScript - Endpoint 1</title>
        <script src="/static/secrets-ep1.js"></script>
    </head>
    <body>
        <h1>Page with Secret in JavaScript - Endpoint 1</h1>
        <p>This page contains a secret API key in a script tag.</p>
        
        <script>
            // Initialize API configuration
            const config = {{
                apiKey: "ep1-{api_key}",
                endpoint: "https://api.example.com",
                timeout: 5000
            }};
            
            // JSON string format
            const jsonData = `{{"secret":"ep1-{api_key_2}"}}`;
            
            // Escaped JSON format
            const escapedJson = "\\"apiKey\\":\\"ep1-{api_key_3}\\"";
            
            // Full URL with secret
            const fullURL = "https://site.com/api.php?secret=ep1-{api_key}&token=ep1-{api_key_2}&page=1";
            
            console.log("API initialized with configuration for endpoint 1");
        </script>
        
        <div style="margin-top: 50px; padding: 20px; background-color: #f0f0f0; border: 1px solid #ccc;">
            <h3>Total Secrets: 6</h3>
            <p>This endpoint contains 6 secrets that should be detected (all prefixed with 'ep1-'):
            <ul>
                <li>1 GitHub token in external secrets-ep1.js file</li>
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
        "endpoint_id": "ep2-aws",
        "data": {
            "user": "testuser",
            "aws_access_key": f"ep2-{aws_key}",
            "region": "us-west-2"
        },
        "config": {
            "json_data": f'{{"aws_secret":"ep2-{aws_key_2}"}}',
            "escaped_json": f'\\"aws_key\\":\\"ep2-{aws_key_3}\\"',
            "full_url": f"https://aws.amazon.com/console?access_key=ep2-{aws_key}&secret=ep2-{aws_key_2}&region=us-east-1"
        },
        "total_secrets": 5,
        "secret_breakdown": {
            "aws_keys_in_json": 3,
            "aws_keys_in_url": 2,
            "note": "All secrets prefixed with 'ep2-'"
        }
    })

@app.route('/3-github')
def endpoint_three():
    github_token = generate_github_token()
    github_token_2 = generate_github_token()
    github_token_3 = generate_github_token()
    
    # Create endpoint-specific secrets file
    endpoint_github_token = create_endpoint_secrets_js("ep3")
    
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>GitHub Token Example - Endpoint 3</title>
        <script src="/static/secrets-ep3.js"></script>
    </head>
    <body>
        <h1>Page with GitHub Token - Endpoint 3</h1>
        <p>This page loads a local secrets-ep3.js file and also contains a GitHub token in the code below:</p>
        
        <pre>
        function authenticateWithGitHub() {{
            // Sample code showing token usage
            const headers = {{
                'Authorization': 'token ep3-{github_token}'
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
            const githubConfig = `{{"github_token":"ep3-{github_token_2}"}}`;
            
            // Escaped JSON format
            const escapedGithubJson = "\\"token\\":\\"ep3-{github_token_3}\\"";
            
            // Full URL with GitHub token
            const githubURL = "https://github.com/api/user?token=ep3-{github_token}&access_token=ep3-{github_token_2}";
            
            console.log("GitHub tokens loaded for endpoint 3");
        </script>
        
        <div style="margin-top: 50px; padding: 20px; background-color: #f0f0f0; border: 1px solid #ccc;">
            <h3>Total Secrets: 6</h3>
            <p>This endpoint contains 6 secrets that should be detected (all prefixed with 'ep3-'):
            <ul>
                <li>1 GitHub token in external secrets-ep3.js file</li>
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
    
    # Create endpoint-specific secrets file
    endpoint_github_token = create_endpoint_secrets_js("ep4")
    
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Multiple Secrets Example - Endpoint 4</title>
        <script src="/static/secrets-ep4.js"></script>
    </head>
    <body>
        <h1>Page with Multiple Secrets - Endpoint 4</h1>
        <p>This page contains multiple different types of secrets for testing detection.</p>
        
        <!-- AWS Key in HTML comment -->
        <!-- AWS Access Key: ep4-{aws_key} -->
        
        <div class="config-section">
            <h2>AWS Configuration</h2>
            <p>Region: us-east-1</p>
            <p>Access Key ID: AKIAIOSFODNN7EXAMPLE</p>
            <p>Secret Access Key: ep4-{aws_key}</p>
        </div>
        
        <script>
            // Initialize API configuration with API key
            const config = {{
                apiKey: "ep4-{api_key}",
                endpoint: "https://api.example.com",
                timeout: 5000
            }};
            
            console.log("API initialized with configuration");
            
            // GitHub token used in JavaScript function
            function authenticateWithGitHub() {{
                const headers = {{
                    'Authorization': 'token ep4-{github_token}'
                }};
                
                fetch('https://api.github.com/user', {{
                    method: 'GET',
                    headers: headers
                }})
                .then(response => response.json())
                .then(data => console.log(data));
            }}
            
            // JSON string formats
            const awsConfig = `{{"aws_access_key":"ep4-{aws_key_2}","region":"us-west-2"}}`;
            const apiConfig = `{{"api_key":"ep4-{api_key_2}","timeout":5000}}`;
            const githubConfig = `{{"github_token":"ep4-{github_token_2}"}}`;
            
            // Escaped JSON formats
            const escapedAws = "\\"aws_key\\":\\"ep4-{aws_key}\\"";
            const escapedApi = "\\"apiKey\\":\\"ep4-{api_key_2}\\"";
            const escapedGithub = "\\"github_token\\":\\"ep4-{github_token_2}\\"";
            
            // Full URLs with secrets
            const awsURL = "https://console.aws.amazon.com/s3?access_key=ep4-{aws_key}&secret=ep4-{aws_key_2}";
            const apiURL = "https://api.service.com/endpoint?key=ep4-{api_key}&token=ep4-{api_key_2}";
            const githubURL = "https://api.github.com/repos/user/repo?token=ep4-{github_token}&access_token=ep4-{github_token_2}";
        </script>
        
        <h3>Sample Code</h3>
        <pre>
        // Example GitHub authentication
        const githubAuth = {{
            token: "ep4-ghp_{github_token[4:]}",
            username: "testuser"
        }};
        </pre>
        
        <div style="margin-top: 50px; padding: 20px; background-color: #f0f0f0; border: 1px solid #ccc;">
            <h3>Total Secrets: 17</h3>
            <p>This endpoint contains 17 secrets that should be detected (all prefixed with 'ep4-'):
            <ul>
                <li>1 GitHub token in external secrets-ep4.js file</li>
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
    
    # Create endpoint-specific secrets file with static token
    filename = f'static/secrets-ep6.js'
    static_github_token = "ghp_ep6_StaticTokenForTesting1234567890ABC"
    
    with open(filename, 'w') as f:
        f.write(f'''// Configuration file for endpoint 6 (static secrets)
const API_SETTINGS = {{
    timeout: 30000,
    retries: 3,
    github_token: "{static_github_token}",
    endpoint_id: "ep6-static"
}};

const ENDPOINT_SECRET = "ep6-static-{static_github_token}";
''')
    
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Static Secrets Example - Endpoint 6</title>
        <script src="/static/secrets-ep6.js"></script>
    </head>
    <body>
        <h1>Page with Static Secrets - Endpoint 6</h1>
        <p>This page contains static secrets that never change between requests.</p>
        
        <div class="config-section">
            <h2>AWS Configuration</h2>
            <p>Region: us-east-1</p>
            <p>Secret Access Key: ep6-{aws_key}</p>
        </div>
        
        <script>
            // GitHub token used in JavaScript function
            function authenticateWithGitHub() {{
                const headers = {{
                    'Authorization': 'token ep6-{github_token}'
                }};
                
                fetch('https://api.github.com/user', {{
                    method: 'GET',
                    headers: headers
                }})
                .then(response => response.json())
                .then(data => console.log(data));
            }}
            
            // JSON string formats
            const awsData = `{{"aws_access_key":"ep6-{aws_key_2}"}}`;
            const githubData = `{{"github_token":"ep6-{github_token_2}"}}`;
            
            // Escaped JSON formats
            const escapedAwsJson = "\\"aws_secret\\":\\"ep6-{aws_key}\\"";
            const escapedGithubJson = "\\"token\\":\\"ep6-{github_token_2}\\"";
            
            // Full URLs with secrets
            const awsConsoleURL = "https://console.aws.amazon.com/iam?access_key=ep6-{aws_key}&secret_key=ep6-{aws_key_2}";
            const githubApiURL = "https://api.github.com/user/repos?token=ep6-{github_token}&access_token=ep6-{github_token_2}";
        </script>
        
        <div style="margin-top: 50px; padding: 20px; background-color: #f0f0f0; border: 1px solid #ccc;">
            <h3>Total Secrets: 11</h3>
            <p>This endpoint contains 11 secrets that should be detected (all prefixed with 'ep6-'):
            <ul>
                <li>1 GitHub token in external secrets-ep6.js file</li>
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
    
    # Create endpoint-specific secrets file
    endpoint_github_token = create_endpoint_secrets_js("ep7")
    
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Fixed Pattern Secrets Example - Endpoint 7</title>
        <script src="/static/secrets-ep7.js"></script>
    </head>
    <body>
        <h1>Page with Properly Formatted Secrets - Endpoint 7</h1>
        <p>This page contains secrets formatted to match our regex patterns.</p>
        
        <div class="config-section">
            <h2>AWS Configuration</h2>
            <p>Region: us-east-1</p>
            <p>AWS Access Key: ep7-{aws_key}</p>
        </div>
        
        <div class="config-section">
            <h2>GCP Configuration</h2>
            <p>GCP API Key: ep7-{gcp_key}</p>
        </div>
        
        <div class="config-section">
            <h2>GitHub Configuration</h2>
            <p>GitHub PAT: ep7-{github_token}</p>
        </div>
        
        <script>
            // JSON string formats
            const awsConfig = `{{"aws_access_key":"ep7-{aws_key_2}","region":"us-west-2"}}`;
            const gcpConfig = `{{"gcp_api_key":"ep7-{gcp_key_2}","project":"test-project"}}`;
            const githubConfig = `{{"github_token":"ep7-{github_token_2}","username":"testuser"}}`;
            
            // Escaped JSON formats
            const escapedAws = "\\"aws_key\\":\\"ep7-{aws_key}\\"";
            const escapedGcp = "\\"gcp_key\\":\\"ep7-{gcp_key_2}\\"";
            const escapedGithub = "\\"github_token\\":\\"ep7-{github_token_2}\\"";
            
            // Full URLs with secrets
            const awsURL = "https://s3.amazonaws.com/bucket?AWSAccessKeyId=ep7-{aws_key}&SecretKey=ep7-{aws_key_2}";
            const gcpURL = "https://googleapis.com/storage/v1/b/bucket?key=ep7-{gcp_key}&api_key=ep7-{gcp_key_2}";
            const githubURL = "https://api.github.com/user?token=ep7-{github_token}&access_token=ep7-{github_token_2}";
            
            console.log("All cloud service tokens loaded for endpoint 7");
        </script>
        
        <div style="margin-top: 50px; padding: 20px; background-color: #f0f0f0; border: 1px solid #ccc;">
            <h3>Total Secrets: 16</h3>
            <p>This endpoint contains 16 secrets that should be detected (all prefixed with 'ep7-'):
            <ul>
                <li>1 GitHub token in external secrets-ep7.js file</li>
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
        <title>Fixed Pattern Secrets Example - NPM - Endpoint 8</title>
    </head>
    <body>
        <h1>Page with Properly Formatted NPM Secrets - Endpoint 8</h1>
        <p>This page contains NPM secrets formatted to match our regex patterns.</p>
        
        <div class="config-section">
            <h2>NPM Configuration</h2>
            <p>NPM Token: ep8-{npm_token}</p>
        </div>
        
        <script>
            // JSON string format
            const npmConfig = `{{"npm_token":"ep8-{npm_token_2}","registry":"https://registry.npmjs.org"}}`;
            
            // Escaped JSON format
            const escapedNpmJson = "\\"npm_token\\":\\"ep8-{npm_token}\\"";
            
            // Full URL with NPM token
            const npmURL = "https://registry.npmjs.org/package?token=ep8-{npm_token}&auth_token=ep8-{npm_token_2}";
            
            console.log("NPM configuration loaded for endpoint 8");
        </script>
        
        <div style="margin-top: 50px; padding: 20px; background-color: #f0f0f0; border: 1px solid #ccc;">
            <h3>Total Secrets: 5</h3>
            <p>This endpoint contains 5 secrets that should be detected (all prefixed with 'ep8-'):
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

@app.route('/secret-registry')
def secret_registry():
    """Show all generated secrets and their sources for testing"""
    return jsonify(SECRET_REGISTRY)

@app.route('/')
def index():
    """Show an index of all available endpoints"""
    endpoints = [
        {"path": "/1", "name": "API Key in JavaScript", "secrets": 6},
        {"path": "/2-aws", "name": "AWS Access Key in JSON Response", "secrets": 5},
        {"path": "/3-github", "name": "GitHub Token Example", "secrets": 6},
        {"path": "/4-all", "name": "Multiple Secrets Example", "secrets": 17},
        {"path": "/6-static-aws-github", "name": "Static AWS and GitHub Secrets", "secrets": 11},
        {"path": "/7-fixed-patterns-aws-github-gcp", "name": "Fixed Pattern Secrets (AWS, GitHub, GCP)", "secrets": 16},
        {"path": "/8-fixed-patterns-no-groups-npm", "name": "Fixed Pattern Secrets - No Groups (NPM)", "secrets": 5},
        {"path": "/secret-registry", "name": "📋 Secret Registry (for testing identification)", "secrets": "All"}
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
            .secret-count {
                font-weight: bold;
                color: #cc0000;
            }
        </style>
    </head>
    <body>
        <h1>Secret Detection Test Server</h1>
        <p>Click on any endpoint below to generate a test response containing various secrets:</p>
        <p><strong>Note:</strong> Each endpoint now has unique secrets with prefixes (ep1-, ep2-, etc.) to identify which endpoint generated which finding in Burp!</p>
        <ul>
    '''
    
    for endpoint in endpoints:
        html_content += f'''
            <li>
                <a href="{endpoint['path']}">{endpoint['path']}</a>
                <div class="description">{endpoint['name']} - <span class="secret-count">{endpoint['secrets']} secrets</span></div>
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
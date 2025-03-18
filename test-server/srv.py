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
            
            console.log("API initialized with configuration");
        </script>
    </body>
    </html>
    '''
    return render_template_string(html_content)

@app.route('/2-aws')
def endpoint_two():

    aws_key = generate_aws_key()
    return jsonify({
        "status": "success",
        "data": {
            "user": "testuser",
            "aws_access_key": aws_key,
            "region": "us-west-2"
        }
    })

@app.route('/3-github')
def endpoint_three():
    github_token = generate_github_token()
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
        </script>
        
        <h3>Sample Code</h3>
        <pre>
        // Example GitHub authentication
        const githubAuth = {{
            token: "ghp_{github_token[4:]}",
            username: "testuser"
        }};
        </pre>
    </body>
    </html>
    '''
    return render_template_string(html_content)

@app.route('/6-static-aws-github')
def endpoint_six_static():
    # Static, non-random secrets for consistent testing
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    github_token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
    
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Static Secrets Example</title>
    </head>
    <body>
        <h1>Page with Static Secrets</h1>
        <p>This page contains two static secrets that never change between requests.</p>
        
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
        </script>
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
        {"path": "/7-fixed-patterns-aws-github-gcp", "name": "Fixed Pattern Secrets (AWS, GitHub, GCP)"}
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
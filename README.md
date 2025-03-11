# Burp AI Secrets Detector
Burp extension that automatically detects leaked secrets in HTTP responses. The extension uses a dual-detection approach combining fixed patterns and a sophisticated randomness analysis algorithm to find exposed secrets with minimal false positives.

## Installation

1. Download the jar file from [burp-ai-secrets-detector-1.0.0.jar](https://github.com/slicingmelon/burp-ai-secrets-detector/blob/main/build/libs/burp-ai-secrets-detector-1.0.0.jar)
2. In burp, add the .jar file: Burp → Extensions → Installed → Add → Select .jar file

## How It Works

The extension scans HTTP responses for leaked secrets using two complementary detection mechanisms:

### 1. Fixed Pattern Detection

The extension contains a comprehensive set of regular expressions designed to match known secret formats, including:

- AWS Access Keys (AKIA...)
- GitHub Personal Access Tokens (ghp_...)
- GitLab Tokens (glpat-...)
- Stripe API Keys
- Square OAuth Tokens
- JWT/JWE Tokens
- GCP API Keys
- Various private key formats (RSA, DSA, EC, SSH, etc.)
- And more


### 2. Random String Detection Algorithm

For detecting secrets that don't follow standardized patterns, the extension implements a randomness analysis algorithm ported from RipSecrets. This algorithm:

1. **Identifies potential secrets** by looking for variable assignments matching patterns like `key = "value"`, `token: "value"`, etc.

2. **Analyzes the randomness** of these values using multiple statistical techniques:
   - **Character class distribution**: Checks if the distribution of uppercase, lowercase, and numeric characters matches what would be expected in random strings
   - **Distinct value analysis**: Analyzes the cardinality of unique characters
   - **Bigram frequency analysis**: Examines pairs of adjacent characters to determine if they follow natural language patterns or appear random
   - **Entropy calculation**: Evaluates the randomness of the detected string

3. **Filters false positives** by requiring detected strings to:
   - Have a minimum length (15 characters)
   - Contain at least one digit
   - Pass a randomness probability threshold

This dual-detection approach provider high accuracy in finding both common and random secrets or API keys that might be hardcoded in HTTP responses.

## Content Type Filtering

The scanning phase is set to skip binary content types (images, videos, fonts, etc.) where secrets are unlikely to be found.

## Configuration

The extension allows you to configure:
- Number of worker threads for background scanning
- Whether to scan only in-scope targets
- Which Burp tools to enable scanning for (Proxy, Scanner, Extensions, Repeater, etc.)

## Optimizations

The extension includes several optimizations for performance and resource efficiency:

- **Temporary Response Storage**: Each HTTP response is saved to a temporary file using Burp's `copyToTempFile()` method before processing, avoiding large memory allocations that could impact Burp's performance
- **Multi-threaded Processing**: Configurable worker threads scan responses in parallel
- **Content Type Filtering**: Binary files such as images, videos, audio, and other non-text formats are automatically excluded from scanning to improve performance
- **Deduplication Algorithm**: A custom deduplication implementation tracks previously discovered secrets to prevent redundant issue reports for the same endpoint
- **Memoization**: Complex probability calculations in the randomness detection algorithm use memoization to avoid redundant computation

These optimizations ensure the extension remains lightweight and responsive even when processing large volumes of traffic.

## TO DO

- The extension needs thorough testing to minimize false positives before enabling AI integration, as each false positive would unnecessarily consume tokens.
- While it's not currently possible to use custom AI models through the Montoya API, and Burp's built-in AI is a paid service with token limitations, the next version will have the option to leverage Burp's AI for additional verification of detected secrets once the base detection rate is refined.
  
## Credits

This extension is inspired by and ports the randomness detection algorithm from [RipSecrets](https://github.com/sirwart/ripsecrets), a tool designed to find secrets accidentally committed to repositories.
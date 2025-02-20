# SSL Security Analyzer

A web-based tool for analyzing SSL/TLS security configurations of domains
## Features

- Regular security analysis of domains
- SHA-256 negotiation testing
- Visualization of security status with detailed reports
- Batch processing of multiple domains
- Copy-to-clipboard functionality for eligible domains

## Requirements

- Python 3.7+
- Flask
- pyOpenSSL
- Standard SSL/TLS libraries

## Installation

1. Clone the repository or download the source files
```bash
git clone https://github.com/yourusername/ssl-security-analyzer.git
cd ssl-security-analyzer
```

2. Create and activate a virtual environment (recommended)
```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate
```

3. Install the required dependencies
```bash
pip install flask pyopenssl
```

## Project Structure

```
ssl-security-analyzer/
├── app.py            # Main Flask application
├── templates/        # HTML templates directory
│   └── index.html    # Main UI template
├── static/           # Static files (if any)
├── README.md         # This file
└── requirements.txt  # Dependencies file
```

## Usage

1. Make sure the template file is in the correct location:
   - Create a `templates` directory if it doesn't exist
   - Place the HTML content from `paste-2.txt` into `templates/index.html`

2. Start the Flask application
```bash
python app.py
```

3. Access the application in your web browser
```
http://localhost:8000
```

## Features Usage

### Regular Analysis
1. Navigate to the "Regular Analysis" tab
2. Enter domain names separated by commas (e.g., `google.com, microsoft.com, github.com`)
3. Click "Analyze Security"
4. Review the results, which will show:
   - Whether domains can be removed from proxy
   - TLS version and cipher suite information
   - Certificate details and validation
   - Security compliance status

### SHA-256 Negotiation Test
1. Navigate to the "SHA-256 Negotiation Test" tab
2. Enter domain names separated by commas
3. Click "Test SHA-256 Negotiation"
4. Review the results, which will show:
   - Whether domains can negotiate down to SHA-256
   - Comparison between standard connection and SHA-256 restricted connection
   - Certificate details

## Troubleshooting

### Common Issues

1. **Connection Timeouts**: 
   - Check your network connection
   - Verify the domain names are correct
   - Some domains may have restrictive security policies that block analysis

2. **SSL Library Errors**:
   - Ensure you have the latest version of pyOpenSSL
   - Update your system's OpenSSL libraries if needed

3. **Flask Application Not Starting**:
   - Check if port 8000 is already in use
   - Make sure you have the correct permissions to bind to the port

## Security Considerations

This tool performs passive analysis of publicly available SSL/TLS configurations and does not:
- Perform any attacks against the target domains
- Store or transmit analyzed data outside your local environment
- Modify any server configurations

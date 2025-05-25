# SmartZone Firewall Profile Web App - Deployment Guide

This guide explains how to deploy the SmartZone Firewall Profile web application to Google Cloud Platform using App Engine (free tier).

## Prerequisites

1. **Google Cloud Account**: Create a free account at https://cloud.google.com
2. **gcloud CLI**: Install from https://cloud.google.com/sdk/docs/install
3. **Python 3.9+**: Required for local testing

## Quick Deployment

```bash
# Run the deployment script
./deploy.sh
```

## Manual Deployment Steps

### 1. Set Up Google Cloud Project

```bash
# Login to Google Cloud
gcloud auth login

# Create a new project (or use existing)
gcloud projects create YOUR_PROJECT_ID --name="SmartZone Firewall"

# Set the project as active
gcloud config set project YOUR_PROJECT_ID

# Enable billing (required for App Engine)
# Visit: https://console.cloud.google.com/billing

# Enable required APIs
gcloud services enable appengine.googleapis.com
```

### 2. Initialize App Engine

```bash
# Initialize App Engine in your preferred region
gcloud app create --region=us-central1
```

Available regions for free tier:
- `us-central1` (Iowa)
- `us-east1` (South Carolina)
- `us-west1` (Oregon)

### 3. Deploy the Application

```bash
# Deploy to App Engine
gcloud app deploy app.yaml

# View your app
gcloud app browse
```

**Note**: The application includes `main.py` as an entry point for gunicorn, which is required for App Engine deployment.

## Configuration

### Environment Variables

Set production secrets in App Engine:

```bash
# Generate a secure secret key
python -c "import secrets; print(secrets.token_hex(32))"

# Add to app.yaml
echo "env_variables:" >> app.yaml
echo "  SECRET_KEY: 'your-generated-secret-key'" >> app.yaml
```

### Custom Domain

To use a custom domain (e.g., szacl.yourdomain.com):

#### 1. Add CNAME Record
In your domain registrar (e.g., Namecheap):
- Type: `CNAME`
- Host: `szacl` (or your chosen subdomain)
- Value: `ghs.googlehosted.com`
- TTL: Automatic

#### 2. Create Domain Mapping
```bash
# Add custom domain to App Engine
gcloud app domain-mappings create szacl.yourdomain.com

# Check domain mapping status
gcloud app domain-mappings describe szacl.yourdomain.com
```

#### 3. Verify Domain (if needed)
If prompted, add the TXT record to your DNS:
- For root domain verification: Host = `@`
- For subdomain verification: Host = subdomain name

#### 4. SSL Certificate
Google automatically provisions and manages SSL certificates:
- No manual configuration needed
- Usually ready within 15-60 minutes
- Check status in `sslSettings` when describing domain mapping

#### 5. Verify DNS
```bash
# Check CNAME record
dig +short szacl.yourdomain.com CNAME

# Should return: ghs.googlehosted.com.
```

## Free Tier Limits

Google App Engine free tier includes:
- **28 instance hours per day** (F1 instance class)
- **1 GB outgoing traffic per day**
- **1 GB incoming traffic per day**
- **5 GB Cloud Storage**

## Monitoring

### View Logs

```bash
# Stream logs
gcloud app logs tail -s default

# View recent logs
gcloud app logs read
```

### Dashboard

Visit the [App Engine Dashboard](https://console.cloud.google.com/appengine) to:
- Monitor traffic and errors
- View resource usage
- Manage versions

## Local Development

### Set Up Local Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Run Locally

```bash
# Run the Flask development server
python app.py

# Or use gunicorn (production-like)
gunicorn app:app --bind 0.0.0.0:8080
```

Visit http://localhost:8080

## Security Considerations

1. **HTTPS**: App Engine automatically provides HTTPS
2. **Credentials**: Never store SmartZone credentials - they're only used temporarily
3. **File Uploads**: Files are stored temporarily and cleaned up after processing
4. **Rate Limiting**: Consider adding rate limiting for production use

## Troubleshooting

### Deployment Fails

```bash
# Check your project configuration
gcloud config list

# Verify billing is enabled
gcloud beta billing projects describe YOUR_PROJECT_ID

# Check App Engine service account permissions
gcloud projects get-iam-policy YOUR_PROJECT_ID
```

#### ModuleNotFoundError
If you see "ModuleNotFoundError" in logs:
- Ensure all required Python files are included in deployment
- Check `.gcloudignore` file - it should NOT exclude files imported by the app
- Required files: `app.py`, `main.py`, `create_firewall_profile.py`, `csv_utils.py`

#### 502 Bad Gateway
If you get 502 errors:
- Check logs: `gcloud app logs tail -s default`
- Ensure `main.py` exists as the entry point
- Verify `app.yaml` has: `entrypoint: gunicorn -b :$PORT main:app`

### Application Errors

```bash
# Check application logs
gcloud app logs read --service=default --limit=50

# SSH into the instance (for debugging)
gcloud app instances ssh INSTANCE_ID --service=default --version=VERSION_ID
```

### File Upload Issues

- Ensure files are under 16MB
- Check that CSV files have correct headers
- Verify JSON files are valid

## Cost Management

To stay within free tier:
1. Set budget alerts in [Google Cloud Console](https://console.cloud.google.com/billing)
2. Monitor daily usage
3. Set up [spending limits](https://cloud.google.com/appengine/docs/standard/python3/console#setting_spending_limits)

## Support

For issues specific to:
- **This application**: Create an issue on the GitHub repository
- **Google Cloud**: Visit [Google Cloud Support](https://cloud.google.com/support)
- **SmartZone API**: Refer to Ruckus documentation
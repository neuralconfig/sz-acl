#!/bin/bash

# SmartZone Firewall Profile Web App - Google Cloud Deployment Script

echo "🚀 SmartZone Firewall Profile Web App Deployment"
echo "=============================================="

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "❌ Error: gcloud CLI is not installed"
    echo "Please install it from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Get current project
CURRENT_PROJECT=$(gcloud config get-value project 2>/dev/null)

if [ -z "$CURRENT_PROJECT" ]; then
    echo "❌ Error: No Google Cloud project is set"
    echo "Run: gcloud config set project YOUR_PROJECT_ID"
    exit 1
fi

echo "📋 Current project: $CURRENT_PROJECT"
echo ""

# Confirm deployment
read -p "Do you want to deploy to project $CURRENT_PROJECT? (y/N) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled"
    exit 0
fi

# Enable required APIs
echo ""
echo "🔧 Enabling required APIs..."
gcloud services enable appengine.googleapis.com

# Initialize App Engine if needed
echo ""
echo "🏗️  Initializing App Engine..."
gcloud app create --region=us-central || echo "App Engine already initialized"

# Deploy the application
echo ""
echo "🚀 Deploying application..."
gcloud app deploy app.yaml --quiet

# Display the app URL
echo ""
echo "✅ Deployment complete!"
echo ""
echo "Your app is available at:"
gcloud app browse --no-launch-browser

echo ""
echo "📝 Next steps:"
echo "1. Visit your app URL to test the deployment"
echo "2. Monitor logs with: gcloud app logs tail -s default"
echo "3. View dashboard: https://console.cloud.google.com/appengine"
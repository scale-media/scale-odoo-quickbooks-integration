#!/bin/bash
#
# Build Lambda deployment packages for Odoo-QB integration with approval flow
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAMBDA_DIR="$SCRIPT_DIR/lambda"
BUILD_DIR="$SCRIPT_DIR/build"

echo "Building Lambda deployment packages..."

# Clean up
rm -rf "$BUILD_DIR"
rm -f "$LAMBDA_DIR"/*.zip

# Create build directory
mkdir -p "$BUILD_DIR/deps"

# Install dependencies
echo "Installing dependencies..."
pip install -r "$LAMBDA_DIR/requirements.txt" -t "$BUILD_DIR/deps" --quiet --upgrade

# Function to build a Lambda package
build_lambda() {
    local name=$1
    local source=$2
    
    echo "Building ${name}.zip..."
    cd "$BUILD_DIR"
    rm -rf "$name" && mkdir "$name"
    cp -r deps/* "$name/"
    cp "$LAMBDA_DIR/$source" "$name/"
    cd "$name"
    zip -r "$LAMBDA_DIR/${name}.zip" . -q
    local size=$(du -h "$LAMBDA_DIR/${name}.zip" | cut -f1)
    echo "    ${name}.zip ($size)"
}

# Build all Lambdas
build_lambda "extractor" "extractor.py"
build_lambda "notifier" "notifier.py"
build_lambda "approval_handler" "approval_handler.py"
build_lambda "poster" "poster.py"

# Cleanup
rm -rf "$BUILD_DIR"

echo ""
echo "Build complete!"
echo ""
echo "Packages created:"
ls -lh "$LAMBDA_DIR"/*.zip

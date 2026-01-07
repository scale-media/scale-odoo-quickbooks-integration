#!/bin/bash
#
# Build Lambda deployment packages for Odoo-QB integration
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAMBDA_DIR="$SCRIPT_DIR/lambda"
BUILD_DIR="$SCRIPT_DIR/build"

echo "🔨 Building Lambda deployment packages..."

# Clean up
rm -rf "$BUILD_DIR"
rm -f "$LAMBDA_DIR/odoo_extractor.zip"
rm -f "$LAMBDA_DIR/qb_poster.zip"

# Create build directory
mkdir -p "$BUILD_DIR/deps"

# Install dependencies (shared between both functions)
echo "📦 Installing dependencies..."
pip install -r "$LAMBDA_DIR/requirements.txt" -t "$BUILD_DIR/deps" --quiet --upgrade

# Build odoo_extractor.zip
echo "📋 Building odoo_extractor.zip..."
cd "$BUILD_DIR"
rm -rf extractor && mkdir extractor
cp -r deps/* extractor/
cp "$LAMBDA_DIR/odoo_extractor.py" extractor/
cd extractor
zip -r "$LAMBDA_DIR/odoo_extractor.zip" . -q
EXTRACTOR_SIZE=$(du -h "$LAMBDA_DIR/odoo_extractor.zip" | cut -f1)
echo "   ✅ odoo_extractor.zip ($EXTRACTOR_SIZE)"

# Build qb_poster.zip
echo "📋 Building qb_poster.zip..."
cd "$BUILD_DIR"
rm -rf poster && mkdir poster
cp -r deps/* poster/
cp "$LAMBDA_DIR/qb_poster.py" poster/
cd poster
zip -r "$LAMBDA_DIR/qb_poster.zip" . -q
POSTER_SIZE=$(du -h "$LAMBDA_DIR/qb_poster.zip" | cut -f1)
echo "   ✅ qb_poster.zip ($POSTER_SIZE)"

# Cleanup
rm -rf "$BUILD_DIR"

echo ""
echo "✅ Build complete!"
echo "   - lambda/odoo_extractor.zip ($EXTRACTOR_SIZE)"
echo "   - lambda/qb_poster.zip ($POSTER_SIZE)"

#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# The directory where build artifacts are stored
OUTPUT_DIR="artifacts"

echo "Generating checksums..."

# Navigate into the artifacts directory to create clean paths in the output file
cd "${OUTPUT_DIR}"

# Generate a SHA256 checksum for all btxz binaries and save to a file
sha256sum btxs-* > sha256sums.txt

echo "✅ Checksums generated successfully in ${OUTPUT_DIR}/sha256sums.txt:"
# Display the contents of the file for logging purposes
cat sha256sums.txt

# Navigate back to the original directory
cd ..

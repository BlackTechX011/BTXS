#!/bin/sh

# BTXS™ Smart Installer Script
#
# This script intelligently detects your system's capabilities to download
# and install the correct version of BTXS.
#
# Usage:
# curl -fsSL https://raw.githubusercontent.com/BlackTechX011/BTXS/main/scripts/install.sh | sh
#
# Copyright (c) 2025-present, BlackTechX011
# Licensed under the BTXS EULA. See https://github.com/BlackTechX011/BTXS/blob/main/LICENSE.md

set -e # Exit immediately if a command exits with a non-zero status.

# --- Configuration ---
REPO="BlackTechX011/BTXS"
INSTALL_DIR="$HOME/.btxs"
PROFILE_FILES="$HOME/.zshrc $HOME/.bashrc $HOME/.profile"
EXE_NAME="btxs"

# --- Helper Functions ---
print_info() {
    printf "\033[1;34m%s\033[0m\n" "$1"
}

print_success() {
    printf "\033[1;32m%s\033[0m\n" "$1"
}

print_error() {
    printf "\033[1;31mError: %s\033[0m\n" "$1" >&2
    exit 1
}

# --- Main Logic ---
main() {
    print_info "Starting BTXS™ installation..."

    # 1. Detect OS and Architecture
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)

    case "$arch" in
        x86_64 | amd64)
            arch="amd64"
            ;;
        aarch64 | arm64)
            arch="arm64"
            ;;
        *)
            print_error "Unsupported architecture: $arch. BTXS currently supports amd64 and arm64."
            ;;
    esac

    # 2. Determine the correct binary suffix based on OS and capabilities
    binary_suffix="" # Default to no suffix (for macOS)

    if [ "$os" = "linux" ]; then
        print_info "Linux detected. Checking GLIBC version for compatibility..."
        
        # Use getconf to check GLIBC version. Fallback to 'compat' if command fails.
        glibc_version=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')
        
        if [ -z "$glibc_version" ]; then
            print_info "Could not determine GLIBC version. Defaulting to the most compatible build."
            binary_suffix="compat"
        else
            # The 'modern' build requires GLIBC >= 2.32. We check if the system's version meets this.
            required_version="2.32"
            
            # Compare versions using sort -V. If the required version is the first line, it's smaller or equal.
            if [ "$(printf '%s\n' "$required_version" "$glibc_version" | sort -V | head -n1)" = "$required_version" ]; then
                print_info "GLIBC version ${glibc_version} is new enough. Selecting 'modern' build."
                binary_suffix="modern"
            else
                print_info "GLIBC version ${glibc_version} is older. Selecting 'compat' build for maximum compatibility."
                binary_suffix="compat"
            fi
        fi
    fi

    # Add a dash only if a suffix was determined
    suffix_dash=""
    if [ -n "$binary_suffix" ]; then
      suffix_dash="-$binary_suffix"
    fi
    
    binary_name="${EXE_NAME}-${os}-${arch}${suffix_dash}"
    print_info "Detected System: ${os}-${arch}. Target binary: ${binary_name}"

    # 3. Get the download URL for the chosen binary
    api_url="https://api.github.com/repos/${REPO}/releases/latest"
    print_info "Fetching latest release information from GitHub..."
    
    # Use curl to fetch and grep/cut to parse JSON without needing jq
    download_url=$(curl -fsSL "$api_url" | grep "browser_download_url" | grep "$binary_name" | cut -d '"' -f 4)

    if [ -z "$download_url" ]; then
        print_error "Could not find a download URL for '$binary_name'. The release may be missing or the API is unavailable."
    fi

    print_info "Download URL: $download_url"

    # 4. Download and install the binary (unchanged from your original script)
    temp_file=$(mktemp)
    print_info "Downloading to a temporary file..."
    curl -fLo "$temp_file" "$download_url"

    install_path="$INSTALL_DIR/$EXE_NAME"
    print_info "Installing to $install_path..."
    mkdir -p "$INSTALL_DIR"
    # Decompress if it's a tar.gz archive
    if [ "${download_url##*.}" = "gz" ]; then
      tar -xzf "$temp_file" -C "$INSTALL_DIR"
      rm "$temp_file"
    else
      mv "$temp_file" "$install_path"
    fi
    chmod +x "$install_path"

    # 5. Add to PATH (unchanged from your original script)
    print_info "Adding installation directory to your shell's PATH..."
    path_export="export PATH=\"$INSTALL_DIR:\$PATH\""
    
    profile_to_update=""
    for profile in $PROFILE_FILES; do
        if [ -f "$profile" ]; then
            profile_to_update="$profile"
            break
        fi
    done

    if [ -z "$profile_to_update" ]; then
        profile_to_update="$HOME/.profile"
        touch "$profile_to_update"
        print_info "Created $profile_to_update as no standard profile was found."
    fi

    if ! grep -q "export PATH=\"$INSTALL_DIR:\$PATH\"" "$profile_to_update"; then
        echo "\n# Added by BTXS installer" >> "$profile_to_update"
        echo "$path_export" >> "$profile_to_update"
        print_info "Updated '$profile_to_update'. Please restart your terminal or run:"
        print_info "  source $profile_to_update"
    else
        print_info "PATH already configured in '$profile_to_update'."
    fi

    print_success "\nBTXS™ was installed successfully!"
    print_info "You can now run '$EXE_NAME' from your terminal."
}

# Run the main function
main

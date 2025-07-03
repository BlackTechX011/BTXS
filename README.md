

<div id="top"></div>
<p align="center">
  <pre>
██████╗ ████████╗██╗  ██╗███████╗
██╔══██╗╚══██╔══╝╚██╗██╔╝██╔════╝
██████╔╝   ██║    ╚███╔╝ ███████╗
██╔══██╗   ██║    ██╔██╗ ╚════██║
██████╔╝   ██║   ██╔╝ ██╗███████║
╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝
                                 
  </pre>
</p>

<h1 align="center">BTXS™ File Splitter</h1>

<p align="center">
  A modern, reliable, high-performance command-line file splitter and merger.
</p>

<p align="center">
    <a href="https://github.com/BlackTechX011/BTXS/releases/latest"><img src="https://img.shields.io/github/v/release/BlackTechX011/BTXS?style=for-the-badge&logo=github&color=blue" alt="Latest Release"></a>
    <a href="https://github.com/BlackTechX011/BTXS/blob/main/LICENSE.md"><img src="https://img.shields.io/github/license/BlackTechX011/BTXS?style=for-the-badge&color=lightgrey" alt="License"></a>
    <a href="https://github.com/BlackTechX011/BTXS/actions/workflows/release.yml"><img src="https://img.shields.io/github/actions/workflow/status/BlackTechX011/BTXS/release.yml?style=for-the-badge&logo=githubactions&logoColor=white" alt="Build Status"></a>
</p>

<p align="center">
  <a href="#-installation">Installation</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-command-reference">Commands</a> •
  <a href="#-contributing">Contributing</a> •
  <a href="#-license">License</a>
</p>

---

**BTXS™** is a professional command-line tool for splitting large files into smaller, more manageable chunks and merging them back together. It's built from the ground up to be reliable and provide a polished user experience, ensuring your data is never corrupted during the process.

> [!NOTE]
> BTXS™ embeds a unique header in every chunk. This allows the `merge` command to automatically find and assemble the correct pieces, even if chunks from multiple different files are in the same directory.

## 🚀 Installation

The recommended way to install BTXS™ is with our one-line installer. It automatically detects your OS and architecture, downloads the correct binary from the latest release, and adds it to your system's PATH.

> [!IMPORTANT]
> The scripts below are the *only* official installation methods. Always download from the official **BlackTechX011/BTXS** repository to ensure you are getting a secure and untampered version of the tool.

---

### Linux / macOS / Termux

This command works on most Unix-like systems, including Debian/Ubuntu, Fedora, Arch, macOS (Intel & Apple Silicon), and Termux on Android.

```sh
curl -fsSL https://raw.githubusercontent.com/BlackTechX011/BTXS/main/scripts/install.sh | sh
```

> [!TIP]
> After installation, you may need to restart your terminal or run `source ~/.zshrc`, `source ~/.bashrc`, etc., to refresh your `PATH` environment variable.

---

### Windows (PowerShell)

> [!NOTE]
> This command temporarily adjusts the execution policy **only for the current process**. It's a safe and standard way to run trusted remote scripts and does not permanently change your system's security settings.

**Open a new PowerShell (as a regular user) and run:**

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; iwr https://raw.githubusercontent.com/BlackTechX011/BTXS/main/scripts/install.ps1 | iex
```
> [!WARNING]
> You **must** open a new PowerShell window after the installation completes. The `PATH` environment variable is only loaded when a new terminal session starts.

<details>
  <summary>Manual Installation</summary>
  
  1. Go to the [**Releases page**](https://github.com/BlackTechX011/BTXS/releases/latest).
  2. Download the appropriate binary for your operating system and architecture (e.g., `btxs-windows-amd64.exe`).
  3. Rename the binary to `btxs` (or `btxs.exe` on Windows).
  4. Move the binary to a directory included in your system's `PATH` (e.g., `/usr/local/bin` on Linux/macOS, or a custom folder on Windows that you add to the Path Environment Variable).
  5. On Linux/macOS, make the binary executable: `chmod +x /usr/local/bin/btxs`.
</details>

## ⚡ Quick Start

Using BTXS™ is designed to be intuitive. Here are the most common operations.

### 1. Split a File

To split a large file into smaller `.btxs` chunks:

```sh
# Split a large backup file into 50MB chunks
btxs split --in database_backup.sql --out ./backup_parts --size 50MB
```

This will create files like `database_backup.0001.btxs`, `database_backup.0002.btxs`, etc.

> [!TIP]
> Use the `-n` or `--name` flag to give your chunks a custom name:
> `btxs split ... --name "project-alpha-backup"`

### 2. Merge Chunks

To reassemble the original file from a directory of chunks:

```sh
# BTXS will automatically find all related .btxs files and merge them
btxs merge --dir ./backup_parts
```

The merged file will be saved in the parent directory as `merged_database_backup.sql`.

## 📖 Command Reference

<details>
  <summary>Click to expand the full command reference</summary>

| Command | Alias | Description | Options |
| :--- | :--- | :--- | :--- |
| `split` | `s` | Splits a file into smaller, encrypted chunks. | `--in <path>` (Required)<br>`--out <dir>`<br>`--size <size>`<br>`--name <name>` |
| `merge`| `m` | Merges `.btxs` chunks back into the original file. | `--dir <dir>` |
| `help`   | `h` | Displays help information for a command. | |

</details>

---

## 🗺️ Project Roadmap

This project is actively developed. Here is a list of planned features. Contributions are welcome!

### Core Features
- [x] Core `split` and `merge` commands
- [x] Data integrity verification via SHA-256
- [x] Smart chunk detection and assembly
- [x] Custom chunk naming
- [ ] Add support for different encryption ciphers (`--cipher`)
- [ ] Implement a `test` command to verify chunk integrity without merging
- [ ] Implement a `repair` command for partially damaged sets (if possible)

### User Experience
- [x] Professional CLI with help and versioning
- [x] Cross-platform build and release workflow
- [ ] Implement self-update mechanism (`btxs update`)
- [ ] Add detailed progress bars for large file operations
- [ ] Add a global configuration file (`~/.config/btxs/config.toml`)

### Documentation & Community
- [x] `LICENSE.md` with custom EULA
- [x] `CONTRIBUTING.md` and Issue Templates
- [ ] Create a GitHub Pages site for full documentation

> **Have an idea or found a bug?** [**Open an issue!**](https://github.com/BlackTechX011/BTXS/issues/new/choose) We'd love to hear from you.

## 🤝 Contributing

Contributions are the backbone of open source. We welcome contributions of all kinds, from filing detailed bug reports to implementing new features.

Before you start, please take a moment to read our guidelines:

-   **[Contribution Guide](CONTRIBUTING.md):** The main guide for how to submit pull requests, our coding standards, and the development process.
-   **[Open an Issue](https://github.com/BlackTechX011/BTXS/issues/new/choose):** The best place to report a bug, ask a question, or propose a new feature.

## 🛡️ Security Model

> [!CAUTION]
> This software is provided "as is" without warranty of any kind. While the lightweight encryption provides obfuscation, it is not a substitute for enterprise-grade cryptographic standards. For highly sensitive data, encrypt the file *before* splitting it.

The security of BTXS™ is a top priority. If you discover a security vulnerability, we ask that you report it to us privately to protect our users.

**Please do not open a public GitHub issue for security-related concerns.**

Instead, send a detailed report directly to: **`BlackTechX@proton.me`**

We will make every effort to respond to your report in a timely manner.

## ⚖️ License

This software is distributed under a custom End-User License Agreement (EULA).

> [!IMPORTANT]
> The license grants permission for **personal, non-commercial use only**. For any other use, including commercial, corporate, or government, please contact the author.

Please see the [**LICENSE.md**](LICENSE.md) file for the full terms and conditions.

---
*BTXS™ is a trademark of [BlackTechX011](https://github.com/BlackTechX011). All rights reserved.*

<p align="right">(<a href="#top">back to top</a>)</p>

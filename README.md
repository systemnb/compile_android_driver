**Read this in other languages: [English](README.md), [中文](README_zh.md).**
# Automated Kernel Driver Builder

This GitHub Action automates the process of building Android kernel drivers in the cloud, eliminating the need for local compilation environments. It solves common issues like accessing Google's source repositories and reduces compilation time to under 30min.

## Key Features

- ✅ **Cloud-based compilation** - No local setup required
- ✅ **Automatic source handling** - Fetches official Android kernel sources
- ✅ **Version-aware building** - Automatically selects correct build system
- ✅ **Parameterized inputs** - Customize builds via workflow inputs
- ✅ **Artifact packaging** - Downloads compiled drivers and kernel images

## Usage Guide

### 1. Repository Setup
1. Create a `code` directory in your repository
2. Place these files in the `code` directory:
   - Driver source files (`.c` and `.h`)
   - `Makefile` for your driver
   - Any additional dependencies

### 2. Running the Workflow
1. Go to your GitHub repository's **Actions** tab
2. Select **Android Kernel Driver Builder**
3. Click **Run workflow**
4. Provide these parameters:
   - `android_version`: Your Android version (Kernel) (e.g., `14`) (for 4.x kernel should be empty)
   - `kernel_version`: Kernel version (e.g., `6.1`)
   - `driver_name`: Your driver filename (e.g., `mydriver.ko`)
   - `target_arch`: Device architecture (default: `aarch64`)

### 3. Retrieving Results
After successful compilation (30minutes):
1. Go to the completed workflow run
2. Download the `kernel-driver-<arch>` artifact
3. Extract to find:
   - Compiled driver (`.ko` file)
   - Kernel images (`boot.img`)
   - Build logs

## Configuration Reference

### Input Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `android_version` | Android OS version | `11`, `12`, `13`, `14`, `15`, `16` |
| `kernel_version` | Linux kernel version | `4.9`, `4.14`, `4.19`, `5.4`, `5.10`, `5.15`, `6.1`, `6.6`, `6.12`, `6.18` |
| `driver_name` | Output driver filename | `custom_driver.ko` |
| `target_arch` | Device CPU architecture | `aarch64`, `x86_64` |

### Technical Notes

1. **Build System Selection**:
   - Android 11 and earlier: Legacy `build.sh` system
   - Android 12 and later: Modern Bazel build system

2. **Source Management**:
   - Automatically fetches kernel sources from Google's repositories
   - Uses parallel downloading for faster sync

3. **Driver Integration**:
   - Automatically adds driver to kernel build system
   - Registers driver as GKI module
   - Handles Makefile modifications

## Troubleshooting

**Q: Build fails with "repo sync" errors**  
A: Retry the workflow. Google's servers can occasionally timeout.

**Q: Driver not found in output artifacts**  
A: Verify:
- Correct `driver_name` parameter (must match Makefile)
- Source files are in `/code` directory
- Makefile produces expected `.ko` filename

**Q: "Kernel configuration not found" error**  
A: Confirm your kernel_version matches existing branches at [Android Kernel Sources](https://android.googlesource.com/kernel/manifest/)

## Support

For issues and feature requests:
- [Open an Issue](https://github.com/systemnb/compile_android_driver/issues)
- Provide workflow logs and input parameters

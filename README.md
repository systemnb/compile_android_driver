# kade – Android Kernel Driver Automation (lyenv-based)

**Read this in other languages: [English](README.md), [中文](README_zh.md).**

kade is an Android kernel driver automation framework built on top of **lyenv**.
It provides a **configuration-driven, reproducible** workflow for building
**GKI** and **non-GKI** kernels locally and in CI (GitHub Actions).

This repository is designed to work with:

- **lyenv**: https://github.com/systemnb/lyenv
- **kade plugin** https://github.com/systemnb/lyenv-plugin-center

---

## Features

- ✅ GKI and non-GKI kernel support
- ✅ Single configuration file (`kadeflow.yaml`)
- ✅ GitHub Actions ready
- ✅ External or in-tree driver integration
- ✅ ABI upstream patching and ABI symbol export
- ✅ Artifact export (modules, images, dist outputs)
- ✅ Optional post-build commands (compile_commands, image unpack, etc.)

---

## Recommended Repository Layout

```text
.
├── code/                     # Driver source directory (external driver)
│   ├── Makefile
│   ├── mydriver.c
│   └── Kconfig               # optional
│
├── abi.symbols               # ABI symbols (optional, recommended)
├── kadeflow.yaml             # Main automation configuration
│
├── .github/
│   └── workflows/
│       └── kade.yml          # GitHub Actions workflow
│
├── README.md
└── README_zh.md
```

---

## Driver Source Directory

When using an **external driver**, kade treats **one directory in the repository**
as the driver source directory.

### Recommended convention

```
code/
```

Configured via:

```yaml
gki:
  driver:
    in_tree: false
    external_src_dir: "${GITHUB_WORKSPACE}/code"
```

Only this directory will be copied into the kernel source tree.
Other repository files are ignored.

> The directory name is **not hardcoded**. Any path may be used.

---

## Providing ABI Symbols (Recommended)

ABI symbols should be version-controlled and reviewed like source code.

### Recommended method: repository file

Create a file such as:

```text
abi.symbols
```

Example:

```text
# ABI symbols required by this driver
register_kprobe
unregister_kprobe
kallsyms_lookup_name
```

Reference it in `kadeflow.yaml`:

```yaml
abi:
  upstream_patch: true
  symbols_file: "${GITHUB_WORKSPACE}/abi.symbols"
```

kade will automatically execute:

```bash
kade abi_upstream
kade abi --file abi.symbols
```

before building.

---

## kadeflow.yaml (Main Configuration)

`kadeflow.yaml` is the **single source of truth** for CI and automation.
All kade configuration is derived from this file.

---

## GKI Configuration

```yaml
kade:
  config_overrides:
    kernel:
      flavor: "gki"

    gki:
      android_version: 13
      kernel_version: "5.15"
      target_arch: "aarch64"

      driver:
        project_name: "mydriver"
        in_tree: false
        external_src_dir: "${GITHUB_WORKSPACE}/code"
        module_name: "mydriver.ko"
        overwrite: true
```

---

## non-GKI Configuration

Enable non-GKI mode:

```yaml
kernel:
  flavor: "non_gki"
```

### Source configuration (`non_gki.source`)

#### Git repository

```yaml
non_gki:
  source:
    type: "repo"
    repo_url: "https://github.com/vendor/kernel.git"
    branch: "main"
```

#### Local directory

```yaml
non_gki:
  source:
    type: "local"
    local_path: "/absolute/path/to/kernel"
```

#### ZIP archive

```yaml
non_gki:
  source:
    type: "zip"
    zip_path: "${GITHUB_WORKSPACE}/kernel.zip"
    zip_strip_root: true
```

---

### Build configuration (`non_gki.build`)

#### Script mode (recommended)

```yaml
non_gki:
  build:
    mode: "script"
    script: "build.sh"
    args: []
    artifacts_dir: "out"
```

#### Make mode (optional)

```yaml
non_gki:
  build:
    mode: "make"
    make:
      defconfig: "vendor_defconfig"
      kernel_series: "4.9_plus"
      toolchain_path_prefix: "/root/toolchain/clang/bin:/root/toolchain/gcc32/bin:/root/toolchain/gcc64/bin"
```

---

### non-GKI compile_commands

non-GKI kernels do not use Bazel.

kade runs:

```bash
python3 gen_compile_commands.py -d <out_dir>
```

Override the directory if needed:

```yaml
compile_commands:
  non_gki_out_dir: "out/android13-5.15/common"
```

---

## Default CI Flow

By default, the GitHub Action will:

1. Install lyenv
2. Create and activate a lyenv project
3. Install the kade plugin
4. Apply configuration from `kadeflow.yaml`
5. Execute:
   - `kade prepare`
   - `kade deps`
   - `kade sync`
   - `kade abi_upstream`
   - `kade abi` (if symbols provided)
   - `kade build`
   - `kade export`
6. Upload exported artifacts

After running:

```bash
eval "$(lyenv activate)"
```

all installed plugins (including `kade`) are available globally.

---

## Environment Variable Expansion

All paths in `kadeflow.yaml` support environment variables such as:

- `${GITHUB_WORKSPACE}`
- `${LYENV_HOME}`

They are expanded automatically before kade runs.

---

##License

- Files under the `code` directory are [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).
- All other parts except the `code` directory are [Apache License 2.0](LICENSE).

Defined by the repository owner.

---

## Related Projects

- lyenv: https://github.com/systemnb/lyenv
- lyenv-plugin-center: https://github.com/systemnb/lyenv-plugin-center
---

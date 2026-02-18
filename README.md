# kade – Android Kernel Driver Automation (lyenv-based)
**Read this in other languages: [English](README.md), [中文](README_zh.md).**
kade is an **Android kernel driver build automation framework** built on top of **lyenv**.
It provides a **reproducible, CI-friendly, configuration-driven** workflow for building
GKI and non-GKI kernel drivers without writing fragile shell scripts.

This repository is intended to be used together with:

- **lyenv**: https://github.com/systemnb/lyenv
- **kade plugin** https://github.com/systemnb/lyenv-plugin-center

---

## Features

- ✅ GKI and non-GKI kernel support
- ✅ Configuration-driven (single YAML file)
- ✅ Fully automated via GitHub Actions
- ✅ External or in-tree driver support
- ✅ ABI upstream patching and ABI symbol export
- ✅ Artifact export (modules, images, dist outputs)
- ✅ Optional post-build commands (compile_commands, image unpack, etc.)

---

## Repository Layout (Recommended)

```text
.
├── code/                     # Driver source directory (external driver)
│   ├── Makefile
│   ├── mydriver.c
│   └── Kconfig               # optional
│
├── abi.symbols               # ABI symbols (optional, recommended)
├── kadeflow.yaml             # Main automation config (required)
│
├── .github/
│   └── workflows/
│       └── kade.yml          # GitHub Actions workflow
│
├── README.md
└── README_zh.md
```

Driver Source Directory
By default, kade treats one directory in the repository as the driver source.
Recommended convention
`code/`

Configured via:

```yaml
gki:
  driver:
    in_tree: false
    external_src_dir: "${GITHUB_WORKSPACE}/code"
```

Only this directory will be copied into the kernel tree.
Other repository files are ignored.

The directory name is not hardcoded. You may use any name as long as the path is correct.

Providing ABI Symbols (Recommended)
ABI symbols should be version-controlled and reviewed like source code.
Recommended method: repository file
Create a file such as:
`abi.symbols`

Example content:
```
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

This will automatically run:
```
kade abi_upstream
kade abi --file abi.symbols
```

before building.

kadeflow.yaml (Main Configuration)
`kadeflow.yaml` is the single source of truth for CI and automation.
Minimal GKI example

```yaml
project:
  name: "ci-kade"
  plugin: "kade"

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

abi:
  upstream_patch: true
  symbols_file: "${GITHUB_WORKSPACE}/abi.symbols"

flow:
  steps:
    - "kade prepare"
    - "kade deps"
    - "kade sync"
    - "kade build"
    - "kade export"
```

Default CI Behavior
The default GitHub Action workflow will:

- Install lyenv
- Create and activate a lyenv project
- Install the kade plugin
- Apply configuration from `kadeflow.yaml`
- Automatically run:
  - `kade prepare`
  - `kade deps`
  - `kade sync`
  - `kade abi_upstream`
  - `kade abi` (if symbols provided)
  - `kade build`
  - `kade export`
- Upload exported artifacts to GitHub Actions

After:
```
eval "$(lyenv activate)"
```
all installed plugins (including kade) are available globally in the environment.

Extending the Flow
Users may add additional commands:

```yaml
flow:
  post_commands:
    - "kade compile_commands"
    - "kade img unpack boot.img --out ${GITHUB_WORKSPACE}/img_out"
```

No workflow changes are required.

Artifacts
Artifacts are uploaded automatically. Typical outputs include:

- Kernel modules (`*.ko`)
- Kernel images (`Image`, `*.dtb`, `*.img`)
- `compile_commands.json`
- Image unpack outputs

Why kade?
Compared to traditional shell-based CI:

| Traditional CI | kade |
| --- | --- |
| Fragile shell scripts | Structured configuration |
| Hard to maintain | Reusable and readable |
| Manual ABI handling | Automated ABI management |
| CI-only logic | Works locally and in CI |

[License](LICENSE)
License is defined by the repository owner.

Related Projects

- lyenv: https://github.com/systemnb/lyenv
- lyenv-plugin-center: https://github.com/systemnb/lyenv-plugin-center
---
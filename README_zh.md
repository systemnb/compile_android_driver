# kade —— 基于 lyenv 的 Android 内核驱动自动化构建

**其他语言版本: [English](README.md), [中文](README_zh.md).**

kade 是一个构建在 **lyenv** 之上的 Android 内核驱动自动化框架，
用于统一、可复现地完成 **GKI / non-GKI** 内核的构建、ABI 处理和产物导出。

该仓库通常配合以下项目使用：

- **lyenv**：https://github.com/systemnb/lyenv
- **kade 插件**: https://github.com/systemnb/lyenv-plugin-center

---

## 特性

- ✅ 支持 GKI / non-GKI 内核
- ✅ 单一配置文件（kadeflow.yaml）
- ✅ 原生支持 GitHub Actions
- ✅ 支持外置驱动 / in-tree 驱动
- ✅ 自动处理 ABI 上游与 ABI 列表
- ✅ 自动导出构建产物
- ✅ 支持构建后扩展命令

---

## 推荐仓库结构

```text
.
├── code/                     # 驱动源码目录（推荐）
│   ├── Makefile
│   ├── mydriver.c
│   └── Kconfig               # 可选
│
├── abi.symbols               # ABI 符号定义（推荐）
├── kadeflow.yaml             # 自动化主配置文件
│
├── .github/
│   └── workflows/
│       └── kade.yml
│
├── README.md
└── README_zh.md
```

---

## 驱动源码目录说明

当使用 **外置驱动** 时，kade 会将仓库中的某一个目录
视为驱动源码目录。

### 推荐约定

```
code/
```

配置方式：

```yaml
gki:
  driver:
    in_tree: false
    external_src_dir: "${GITHUB_WORKSPACE}/code"
```

kade 只会复制该目录，其它文件不会进入内核源码树。

---

## ABI 符号的提供方式（强烈推荐）

ABI 是接口契约，应该作为仓库内容进行管理。

### 推荐方式：仓库文件

创建文件：

```text
abi.symbols
```

示例内容：

```text
register_kprobe
unregister_kprobe
kallsyms_lookup_name
```

在 `kadeflow.yaml` 中引用：

```yaml
abi:
  upstream_patch: true
  symbols_file: "${GITHUB_WORKSPACE}/abi.symbols"
```

构建前将自动执行：

```bash
kade abi_upstream
kade abi --file abi.symbols
```

---

## kadeflow.yaml（核心配置）

`kadeflow.yaml` 是 CI 与本地构建的唯一配置入口。

---

## GKI 配置示例

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
```

---

## non-GKI 配置说明

启用 non-GKI：

```yaml
kernel:
  flavor: "non_gki"
```

### 源码来源（non_gki.source）

```yaml
non_gki:
  source:
    type: "repo"     # repo | local | zip
```

ZIP 示例：

```yaml
non_gki:
  source:
    type: "zip"
    zip_path: "${GITHUB_WORKSPACE}/kernel.zip"
    zip_strip_root: true
```

---

### 构建方式（non_gki.build）

#### script 模式（推荐）

```yaml
non_gki:
  build:
    mode: "script"
    script: "build.sh"
    artifacts_dir: "out"
```

#### make 模式（可选）

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

## non-GKI compile_commands

non-GKI 不使用 Bazel。

kade 执行：

```bash
python3 gen_compile_commands.py -d <out_dir>
```

可通过配置指定目录：

```yaml
compile_commands:
  non_gki_out_dir: "out/android13-5.15/common"
```

---

## 默认 CI 行为

GitHub Actions 默认执行：

   - `kade prepare`
   - `kade deps`
   - `kade sync`
   - `kade abi_upstream`
   - `kade abi` （若提供 symbols）
   - `kade build`
   - `kade export`
   - `上传构建产物`

执行：

```bash
eval "$(lyenv activate)"
```

后，可在任意目录直接使用 `kade`。

---

## 环境变量说明

`kadeflow.yaml` 中的路径支持：

- `${GITHUB_WORKSPACE}`
- `${LYENV_HOME}`

在 CI 中会自动展开。

---

## 许可证

- 目录 `code` 下所有文件为 [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)。
- 除 `code` 目录的其他部分均为 [Apache License 2.0](LICENSE)。

---

## 相关项目

- lyenv：https://github.com/systemnb/lyenv
- lyenv-plugin-center: https://github.com/systemnb/lyenv-plugin-center
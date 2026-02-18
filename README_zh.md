# kade —— 基于 lyenv 的 Android 内核驱动自动化构建
**其他语言版本: [English](README.md), [中文](README_zh.md).**
kade 是一个构建在 **lyenv** 之上的 **Android 内核驱动自动化构建框架**，
用于统一、可复现地完成 GKI / non-GKI 驱动的编译、ABI 处理和产物导出。

该仓库通常配合以下项目使用：

- **lyenv**：https://github.com/systemnb/lyenv
- **kade 插件**: https://github.com/systemnb/lyenv-plugin-center

---

## 核心特性

- ✅ 支持 GKI / non-GKI 内核
- ✅ 单一配置文件驱动（YAML）
- ✅ 原生支持 GitHub Actions
- ✅ 支持外置驱动 / in-tree 驱动
- ✅ 自动处理 ABI 上游与 ABI 列表
- ✅ 自动导出构建产物
- ✅ 支持构建后扩展命令（如导出 compile_commands、解包镜像）

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
│       └── kade.yml          # GitHub Actions
│
├── README.md
└── README_zh.md
```

驱动源码目录说明
在 kade 体系中：

仓库中的某一个目录会被视为“驱动源码目录”

推荐约定
`code/`

在 `kadeflow.yaml` 中指定：

```yaml
gki:
  driver:
    in_tree: false
    external_src_dir: "${GITHUB_WORKSPACE}/code"
```

kade 只会将该目录复制进内核源码树，其它文件不会参与构建。

目录名并非固定，只要路径配置正确即可。

ABI 符号如何提供（强烈推荐）
ABI 是接口契约，应当作为仓库的一部分进行管理。
推荐方式：仓库文件
创建文件：
`abi.symbols`

示例内容：
```
# Driver ABI symbols
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

CI 中将自动执行：
```
kade abi_upstream
kade abi --file abi.symbols
```

✅ 可审查
✅ 可复现
✅ 适合长期维护

kadeflow.yaml（核心配置文件）
`kadeflow.yaml` 是整个自动化流程的唯一配置入口。
最小 GKI 示例

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

默认 CI 行为说明
GitHub Actions 默认会执行以下流程：

- 安装 lyenv
- 创建并激活 lyenv 项目
- 安装 kade 插件
- 应用 `kadeflow.yaml` 中的配置
- 自动执行：
  - `kade prepare`
  - `kade deps`
  - `kade sync`
  - `kade abi_upstream`
  - `kade abi`（若提供 symbols）
  - `kade build`
  - `kade export`
- 将构建产物上传为 CI artifacts

执行：
```
eval "$(lyenv activate)"
```
后，kade 等插件命令在任意目录均可直接使用。

扩展构建流程
用户可在配置中追加命令，例如：

```yaml
flow:
  post_commands:
    - "kade compile_commands"
    - "kade img unpack boot.img --out ${GITHUB_WORKSPACE}/img_out"
```

无需修改 workflow。

构建产物
CI 会自动导出并上传：

- 内核模块（`.ko`）
- 内核镜像与 DTB
- `compile_commands.json`
- 镜像解包结果（如有）

为什么使用 kade？

| 传统 CI | kade |
| --- | --- |
| 脆弱的 shell 脚本 | 结构化配置 |
| ABI 手工维护 | ABI 自动管理 |
| 难以复现 | 本地 / CI 一致 |
| 改动成本高 | 易扩展 |

[License](LICENSE)
License 由仓库维护者自行定义。

相关项目

- lyenv：https://github.com/systemnb/lyenv
- lyenv-plugin-center：https://github.com/systemnb/lyenv-plugin-center
```
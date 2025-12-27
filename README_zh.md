[![Telegram](https://img.shields.io/badge/Follow-Telegram-blue.svg?logo=telegram)](https://t.me/Cycle1337)

**其他语言版本: [English](README.md), [中文](README_zh.md).**
# 自动化内核驱动构建工具
本 GitHub Action 可在云端自动化编译 Android 内核驱动程序，无需本地编译环境。解决访问 Google 源码仓库等问题，编译时间控制在 30min内。

## 核心功能

- ✅ **云端编译** - 无需本地环境配置
- ✅ **自动源码管理** - 从官方仓库获取 Android 内核源码
- ✅ **版本感知构建** - 自动选择正确的构建系统
- ✅ **参数化输入** - 通过工作流参数自定义构建
- ✅ **结果打包** - 下载编译好的驱动和内核镜像

## 使用指南

### 1. 仓库设置
1. 在仓库中创建 `code` 目录
2. 将以下文件放入 `code` 目录：
   - 驱动源文件 (`.c` 和 `.h`)
   - 驱动的 `Makefile`
   - 其他依赖文件

### 2. 运行工作流
1. 转到 GitHub 仓库的 **Actions** 标签页
2. 选择 **Android Kernel Driver Builder**
3. 点击 **Run workflow**
4. 提供以下参数：
   - `android_version`: Android 版本(内核) (例如 `14`) (对于4系内核请留空)
   - `kernel_version`: 内核版本 (例如 `6.1`)
   - `driver_name`: 驱动文件名 (例如 `mydriver.ko`)
   - `target_arch`: 设备架构 (默认 `aarch64`)

### 3. 获取结果
编译成功后 (30 分钟)：
1. 转到完成的工作流运行
2. 下载 `kernel-driver-<架构>` 产物
3. 解压后包含：
   - 编译好的驱动 (`.ko` 文件)
   - 内核镜像 (`boot.img`)
   - 构建日志

## 配置参考

### 输入参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `android_version` | Android 系统版本 | `11`, `12`, `13`, `14`, `15`, `16` |
| `kernel_version` | Linux 内核版本 | `4.9`, `4.14`, `4.19`, `5.4`, `5.10`, `5.15`, `6.1`, `6.6`, `6.12`, `6.18` |
| `driver_name` | 驱动文件名 | `custom_driver.ko` |
| `target_arch` | 设备 CPU 架构 | `aarch64`, `x86_64` |

### 技术说明

1. **构建系统选择**：
   - Android 11 及更早版本：使用传统 `build.sh` 系统
   - Android 12 及更新版本：使用现代 Bazel 构建系统

2. **源码管理**：
   - 自动从 Google 仓库获取内核源码
   - 使用并行下载加速同步过程

3. **驱动集成**：
   - 自动将驱动添加到内核构建系统
   - 注册驱动为 GKI 模块
   - 自动处理 Makefile 修改

## 故障排除

**Q: "repo sync" 步骤失败**  
A: 重新运行工作流，Google 服务器偶尔会出现超时

**Q: 输出产物中找不到驱动文件**  
A: 检查：
- `driver_name` 参数是否正确（需与 Makefile 匹配）
- 源文件是否在 `/code` 目录
- Makefile 是否生成预期的 `.ko` 文件

**Q: 出现 "Kernel configuration not found" 错误**  
A: 确认内核版本在 [Android 内核源码](https://android.googlesource.com/kernel/manifest/) 中存在对应分支

## 支持

问题反馈和功能请求：
- [提交 Issue](https://github.com/Cycle1337/compile_android_driver/issues)
- 请提供工作流日志和输入参数

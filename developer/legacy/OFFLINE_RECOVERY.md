# KDF-1 Recovery Kit — 完全离线恢复

**KDF-1 v1 candidate / NOT FROZEN。** 算法、输入规范、候选向量和派生结果不变。

**KDF-1 算法是离线的，但只有 Recovery Kit 包含所需实现和依赖后，灾难恢复流程
才真正不依赖网络。** 恢复电脑还必须有可用的操作系统，以及匹配的 Python、venv
和 ensurepip。不要把“将来还能运行 pip install”当作备份方案。

## 此次交付的 Kit

本次 Kit 面向 **macOS arm64 / 常规 CPython 3.13（非 free-threaded）**。
wheel 在本机 CPython 3.13.12 下收集并测试；不支持直接拿来装 CPython 3.9/3.14、
Intel Mac、Windows 或 Linux。具体测试状态见 `offline-validation.json` 和
`project/VALIDATION.md`。

包含：

```text
project/                    源码、SPEC、README、候选向量、原测试和恢复工具测试
wheelhouse/                 全部运行依赖和 pip 的 wheel
sdists/                     同版本依赖和 pip 的源码发行包（含原作者许可文件）
runtime/                    可选 Python 离线安装器／源码；此次 macOS 包已包含
requirements-offline.lock   全部运行依赖精确版本 + 当前 wheel SHA-256
bootstrap-pip.lock          pip 25.3 wheel 精确版本 + SHA-256
artifact-provenance.json    下载来源及原发布方文件摘要
bundle-info.json            OS、架构、Python、ABI、版本与验证隔离方式
offline-validation.json    构建后全新 venv 安装／测试记录
SHA256SUMS                 所有文件（除 manifest 本身）的 SHA-256 清单
verify_recovery_kit.py      无第三方依赖的完整性／恢复验证入口
recovery_common.py          标准库校验辅助模块
START_HERE.md               本说明的副本
```

完整运行依赖固定为 argon2-cffi 25.1.0、argon2-cffi-bindings 25.1.0、cffi 2.0.0、
pycparser 2.23。`requirements.txt` 保持原样；`requirements-offline.txt` 记录全部
传递依赖版本，构建时再生成当前平台带哈希的 lock 文件。恢复时只安装 wheel，不运行
source build，不访问 PyPI，不使用 pip 缓存或系统已安装包。

## 第二台电脑：完全断网演练（macOS arm64）

以下操作只使用公开样例，**不要输入真实秘密**。保留原 Kit，验证工作目录放在 Kit 外。

1. 在联网准备阶段，把 ZIP 和独立保管的 `.zip.sha256` 一起复制到两份离线介质。
   同时另存归档摘要到不同位置；SHA-256 可检测损坏，但攻击者同时修改内容和摘要时
   不能证明真实性。此项目没有对 Kit 作数字签名。
2. 到第二台 Apple Silicon Mac，关闭 Wi-Fi、拔掉网线、断开手机共享／其他网络。
   接下来直到测试结束都不联网。操作系统、解压工具和本地终端需要已经可用。
3. 在 ZIP 所在目录执行 `shasum -a 256 -c kdf1-recovery-macos-arm64-cp313.zip.sha256`。
   若归档文件名不同，使用相应 `.sha256` 文件。失败就停止并换用完好副本。
4. 解压 ZIP，进入其中的 Kit 目录。若没有常规 CPython 3.13，可使用保存的
   `runtime/python-3.13.12-macos11.pkg` 安装，启用默认的 pip。它是完整离线安装器，
   不需要 Homebrew。此次归档安装器的 SHA-256 已对照 Python.org 核验；
   **本机未执行安装器，也未在另一台电脑验证安装／Gatekeeper 行为**。请完成这一步
   的实际演练；如系统策略要求联网审批，应在灾难前准备好可离线使用的运行环境。
   不需要为离线恢复运行 `Install Certificates.command` 或安装 Xcode。
5. 以下命令以安装器提供的 Python 路径为例。已有其他 CPython 3.13 时可换成其路径，
   但必须确认在 arm64 模式运行，而不是 Rosetta／free-threaded 构建：

```sh
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13 -c "import platform; print(platform.python_version(), platform.machine())"
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13 -B verify_recovery_kit.py . --check-only
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13 -B verify_recovery_kit.py . --work-dir ../kdf1-offline-rehearsal --report ../kdf1-offline-rehearsal.json
```

`../kdf1-offline-rehearsal` 和报告路径必须尚不存在。此命令会校验完整文件清单、检查目标
平台、创建**全新 venv**，从本地安装 pip 和依赖，执行自检、全部 unittest、公开密码
断言，并再次检查 Kit 未被改写。成功结尾为：

```text
PASS: master_key_hex, site_key_hex, password
Ran 43 tests ... OK
PUBLIC INPUT PASSWORD: HtO+f3SK@_5w*VwW6ufM@UzA
PASS: Recovery Kit installation, tests and public password
```

6. 若要手动重试原测试，进入验证目录的 `project`：

```sh
cd ../kdf1-offline-rehearsal/project
../venv/bin/python -B kdf.py --self-test
../venv/bin/python -B -m unittest -v
../venv/bin/python -B kdf.py
```

交互输入公开样例：Master Phrase=`correct horse battery staple`，Recovery Secret=
`000102030405060708090a0b0c0d0e0f`，label=`example.com`，account=`test`，revision=`1`，
length=`24`。应再次得到 `HtO+f3SK@_5w*VwW6ufM@UzA`。

7. 保存第二台电脑的公开验证报告到 Kit 外。确认没有任何安装步骤需要网络后，才算
   完成这台电脑的恢复演练。真实账户恢复还需要另外核对 2FA 和服务端登录；不要把
   真实材料加入报告、Kit、测试或 Git。

## 手动离线安装方法

推荐使用上面的验证脚本，它会清理继承的 Python/pip 配置并检查 Kit。下面展示核心
命令；在 Kit 目录运行，`../recovery-env` 必须是全新的路径：

```sh
export PIP_CONFIG_FILE=/dev/null
python3.13 -m venv ../recovery-env
../recovery-env/bin/python -I -B -m pip --isolated --disable-pip-version-check --no-cache-dir install --no-index --find-links ./wheelhouse --only-binary=:all: --require-hashes -r bootstrap-pip.lock
../recovery-env/bin/python -I -B -m pip --isolated --disable-pip-version-check --no-cache-dir install --no-index --find-links ./wheelhouse --only-binary=:all: --require-hashes -r requirements-offline.lock
../recovery-env/bin/python -I -B -m pip --isolated --disable-pip-version-check check
cd project
../../recovery-env/bin/python -B kdf.py --self-test
../../recovery-env/bin/python -B -m unittest -v
```

不要删掉 `--no-index`、`--only-binary=:all:` 或 `--require-hashes` 来“修复”安装失败。
缺包、ABI 不匹配、校验不符都应停止；联网准备一份匹配的平台包后，重新断网演练。
`-B` 避免在 Kit 内产生额外缓存文件；严格清单校验也会拒绝新增文件（包括 `.DS_Store`），
所以建议保留原 ZIP 并在 Kit 外工作。

## 自动构建（联网准备阶段）

在**目标 OS、目标 CPU 架构和目标 Python minor 版本**上运行脚本。下载的是已发布
官方依赖 wheel，不实现／重写 Argon2。所有运行依赖与 pip 都必须有匹配 wheel；
缺少任何一个就失败，不静默退回编译。

macOS arm64、CPython 3.13（联网下载；验证子进程由系统禁止网络）：

```sh
python3.13 -B build_recovery_kit.py --output ../kdf1-recovery-macos-arm64-cp313 --include-macos-python --verification-isolation macos-sandbox
```

脚本创建 Kit、同名 ZIP 和 `.zip.sha256`；输出已存在就拒绝覆盖。复制源文件采用
显式白名单，不打包你的 `.venv`、Git 历史、环境变量文件或其他工作目录文件。
使用 `--runtime-file /path/to/trusted-offline-installer` 可明确附加其他平台已核验的
离线安装器（可多次指定）；脚本只复制指定文件并计算摘要，**不会替你证明该文件来源可信**。

`--include-macos-python` 保存与本机测试版本对应的官方 CPython 3.13.12 universal2
安装器和 CPython source tarball，并按代码中固定的 Python.org SHA-256 校验。
这是可复现的归档版本，不宣称是最新 Python；升级运行环境后要重新测试和归档。
其他平台必须自行准备对应的完整离线 Python／OS 安装材料；不要保存只能联网下载
Python 的安装管理器或小型 web installer。未附加安装器的 Kit 要求恢复电脑已有兼容
Python + venv + ensurepip，不能称作“裸机恢复包”。

构建默认会进行本地 wheel-only 安装验证，但默认 `--verification-isolation none`
**没有证明系统网络被关闭**。macOS 可用上述 `macos-sandbox` 选项；Windows/Linux
应在下载构建后，进入禁用网卡的 VM 或物理断网环境，另行运行验证脚本。

## 平台边界：分别构建、分别验证

| 平台 | 自动构建方式 | 本次交付与验证 |
|---|---|---|
| macOS arm64 | 原生 arm64 CPython 上运行脚本 | 已提供 CPython 3.13 wheel Kit；查看验证记录 |
| macOS x86_64 | Intel Mac 的 x86_64 CPython 上运行同脚本 | 未收集／未执行；需在 Intel Mac 独立构建测试 |
| Windows x86_64 | x64 CPython 上运行同脚本，如 `py -3.13 build_recovery_kit.py --output ..\kit-win-cp313` | 未收集／未执行；需 Windows 测试 |
| Linux x86_64 | 目标 Linux 的 CPython 上运行同脚本 | 未收集／未执行；需目标发行版测试，区分 glibc/musl 与版本 |

Windows 恢复：先保留并安装完整离线 x64 CPython，然后在断网 PowerShell 中运行
`py -3.13 -B verify_recovery_kit.py . --work-dir ..\kdf1-offline-rehearsal`。
手动命令把 `venv/bin/python` 换成 `venv\Scripts\python.exe`。
Linux 应预先保存发行版、Python、python-venv/ensurepip 及它们所需系统包，或可离线启动
的完整 VM 镜像；仅保存 `.deb`/`.rpm` 单个文件不保证系统依赖完整。

脚本不提供 `--platform` 跨平台模拟下载。pip 虽然支持跨平台 wheel 下载参数，但
下载成功不能证明目标机器的 ABI、最低 OS 版本、动态库和 Python bootstrap 都可用。
Kit 使用当前运行解释器的实际架构；Apple Silicon 上 Rosetta Python 构建的是 x86_64 包。
macOS 安装器是 universal2，**不代表此 Kit 内的 arm64 CFFI wheel 也适用于 Intel**。
升级 Python minor、操作系统或 CPU 架构时必须准备并演练新的 Kit。

## 源码包的用途与长期保存

`sdists/` 保存运行依赖和 pip 的同版本原始源码，不执行它们的构建脚本。
正常恢复完全不需要这些源码；它们是旧 wheel 将来无法加载时的移植材料。
源码归档保留第三方许可，Argon2 仍来自 argon2-cffi-bindings 上游实现。

源码重建仍可能需要 C 编译器、SDK、libffi、构建后端和它们的依赖；这些不由当前 Kit
完整覆盖。CPython source 同样不包含全部系统工具链。因此不能保证在任意未来 OS/Python
上从源码直接恢复，也不能为了编译成功而悄悄换算法、参数或规范。未来移植必须逐项
验证相同 reference vector 与测试，并保留现在能实际运行的环境／VM／硬件备份。

保留至少两份离线副本，定期核验 SHA-256 和恢复演练。秘密恢复材料与软件 Kit 分开保管。
即使依赖网站消失，现有匹配运行环境与保存的文件仍足以执行已验证流程；若连匹配 OS
也不可用，软件包无法单独替代操作系统和硬件。

## Integrity and offline scope (English)

The KDF algorithm is offline; disaster recovery is network-independent only when
the implementation, dependencies and a compatible Python/OS are already preserved.
This release ships a native macOS arm64 CPython 3.13 kit. Other platforms must be
built and rehearsed natively. Runtime installers are archived, not automatically
installed or proven to work on another machine.

The builder pins all dependencies, collects native wheels plus source distributions,
checks upstream hashes, generates hash-locked local requirements and SHA256SUMS,
and tests a brand-new venv using no index or cache. macOS sandbox mode denies network
for the verification process and its children. Plain no-index mode alone is not a
claim of OS network isolation. Keep a trusted ZIP digest separately; a manifest
detects corruption but is not a signature or protection against replacement of both.

Never put real phrases, Recovery Secrets, keys, passwords or recovery codes into
the Kit, source tree, tests or reports. Status remains candidate / NOT FROZEN.

References: [pip download](https://pip.pypa.io/en/stable/cli/pip_download/),
[pip hash-checking mode](https://pip.pypa.io/en/stable/topics/secure-installs/),
[archived CPython release](https://www.python.org/downloads/release/python-31312/).

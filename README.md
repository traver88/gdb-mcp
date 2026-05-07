# gdb-mcp

`gdb-mcp` 是一个基于 **MCP（Model Context Protocol）** 的高权限 GDB 调试服务端，使用 `pygdbmi` 驱动本地 GDB，并将常见调试动作封装成结构化工具，适用于：

- 本地授权调试
- CTF / Pwn 分析
- Core Dump 分析
- ELF 信息提取
- 远程 `gdbserver` 调试
- 崩溃现场排查
- 会话快照与自动化调试

项目当前面向 **Python 3.12+**。

---

## 1. 设计目标

这个项目的目标不是替代 GDB，而是提供一个适合模型和自动化系统调用的、**有风险分级、可结构化返回、可远程调试、可渐进扩展** 的 GDB 控制层。

核心特性：

- 基于 MCP 暴露调试工具
- 统一 JSON 返回格式
- 对高风险操作进行确认门控
- 支持本地与远程 `gdbserver`
- 支持只读模式
- 支持块级内存写入
- 支持会话快照与能力查询
- 支持原始 GDB CLI / MI 命令
- 支持崩溃分析、ELF 检查和 pwndbg 兼容命令

---

## 2. 当前项目结构

```text
server.py             # MCP 聚合入口
server_runtime.py     # 共享运行时、控制器、公共 helper
tools_session.py      # 会话与加载工具
tools_memory.py       # 内存相关工具
tools_meta.py         # 快照与能力工具
tools_remote.py       # 远程调试与上下文工具
tools_control.py      # 寄存器、断点、运行控制工具
tools_advanced.py     # 原始命令、分析、ELF、插件兼容工具
gdb_controller.py     # GDB/MI 控制器
safety.py             # 风险评估规则
models.py             # 统一响应模型
config.py             # 环境变量配置
utils.py              # 解析与辅助函数
tests/                # unittest + smoke test
examples/             # 示例程序
```

---

## 3. 安装

### 3.1 克隆仓库

```bash
git clone <repo-url>
cd gdb-mcp
```

### 3.2 创建虚拟环境并安装

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

如果你要运行测试：

```powershell
pip install -e .[dev]
```

### 3.3 安装 GDB

确保本机可执行：

```bash
gdb --version
```

Windows 下常见方案是使用 MSYS2：

```bash
pacman -Syu
pacman -S gdb gdb-multiarch
```

然后把 GDB 所在目录加入 `PATH`。

---

## 4. 启动方式

### 4.1 直接启动 MCP 服务

```bash
python server.py
```

或通过安装后的脚本：

```bash
gdb-mcp
```

### 4.2 在 MCP 客户端中配置

示例：

```toml
[mcp_servers.gdb-mcp]
command = "D:\\gdb-mcp\\.venv\\Scripts\\python.exe"
args = ["D:\\gdb-mcp\\server.py"]
```

只要客户端支持 stdio MCP server，就可以用相同方式接入。

---

## 5. 环境变量配置

所有配置项都可以通过 `GDB_MCP_` 前缀环境变量覆盖。

### 常用配置

| 变量 | 说明 | 默认值 |
|---|---|---|
| `GDB_MCP_GDB_PATH` | GDB 可执行路径 | `gdb` |
| `GDB_MCP_DEFAULT_TIMEOUT` | 默认命令超时 | `10` |
| `GDB_MCP_DEFAULT_REMOTE_TIMEOUT` | 远程调试超时 | `10` |
| `GDB_MCP_MAX_MEMORY_READ` | 单次最大内存读取阈值 | `4096` |
| `GDB_MCP_MAX_MEMORY_WRITE` | 单次最大内存写入阈值 | `4096` |
| `GDB_MCP_MAX_MEMORY_DUMP_WITHOUT_CONFIRM` | 免确认 dump 阈值 | `4096` |
| `GDB_MCP_MAX_STEP_COUNT` | 最大步进数量 | `1000` |
| `GDB_MCP_REMOTE_DEBUG_ENABLED` | 是否启用远程调试 | `true` |
| `GDB_MCP_ENABLE_RAW_GDB_EXEC` | 是否启用原始 GDB CLI | `true` |
| `GDB_MCP_ENABLE_RAW_GDB_MI` | 是否启用原始 GDB/MI | `true` |
| `GDB_MCP_ENABLE_PWNDBG_COMMANDS` | 是否启用 pwndbg/gef/peda 兼容命令 | `true` |
| `GDB_MCP_READ_ONLY_MODE` | 是否启用只读模式 | `false` |
| `GDB_MCP_BLOCK_MEMORY_WRITE_CHUNK_SIZE` | 字节写入回退时的分块粒度 | `256` |
| `GDB_MCP_DEFAULT_REMOTE_MODE` | 默认远程模式 | `remote` |

### 只读模式

开启后，会阻止有状态修改类操作，例如：

- `gdb_memory(action="write")`
- `gdb_memory(action="write_block")`
- `gdb_register(action="write")`
- `gdb_breakpoint(action="add")`
- `gdb_run_control(action="run")`

示例：

```powershell
$env:GDB_MCP_READ_ONLY_MODE = "true"
python server.py
```

---

## 6. 统一返回格式

所有工具都返回统一 JSON：

```json
{
  "ok": true,
  "tool": "gdb_memory",
  "action": "read",
  "risk_level": "low",
  "need_confirm": false,
  "executed_with_risk": false,
  "warning": null,
  "data": {},
  "stdout": "",
  "stderr": "",
  "raw": {},
  "error": null
}
```

字段说明：

- `ok`：工具是否成功
- `tool`：工具名
- `action`：子动作名
- `risk_level`：风险级别
- `need_confirm`：是否需要再次以 `confirm=true` 执行
- `executed_with_risk`：是否在确认后执行了风险操作
- `warning`：风险说明
- `data`：结构化结果
- `stdout` / `stderr`：底层 GDB 输出
- `raw`：原始记录
- `error`：错误描述

---

## 7. 当前全部可用工具

### 7.1 会话与加载

#### `gdb_session`

用于管理 GDB 会话：

- `start`
- `stop`
- `restart`
- `status`

```python
gdb_session(action="start")
gdb_session(action="status")
```

#### `gdb_load`

加载本地二进制、core 文件、符号文件和参数。

```python
gdb_load(binary="E:/ctf/pwn/pwn", args=["a", "b"])
```

---

### 7.2 内存工具

#### `gdb_memory(action="read")`

```python
gdb_memory(action="read", address="$rsp", size=128)
```

#### `gdb_memory(action="write")`

```python
gdb_memory(action="write", address="0x404000", data_hex="41424344", confirm=True)
```

#### `gdb_memory(action="write_block")`

块级写入，优先走 `restore ... binary`：

```python
gdb_memory(action="write_block", address="0x404000", data_hex="414243444546", confirm=True)
```

返回中会附带：

- `write_mode`
- `executed_command`
- `byte_count`
- `partial_write_possible`

#### `gdb_memory(action="search")`

```python
gdb_memory(action="search", address="$rsp", size=256, pattern="41414141")
```

#### `gdb_memory(action="dump")`

```python
gdb_memory(action="dump", address="0x404000", size=512, confirm=True)
```

---

### 7.3 元工具

#### `gdb_snapshot`

支持：

- `show`
- `save`
- `list`
- `restore`

```python
gdb_snapshot(action="save", name="crash_case_1")
gdb_snapshot(action="list")
gdb_snapshot(action="restore", name="crash_case_1")
```

当前行为：

- 将快照保存到工作目录下的 `.gdb-mcp-snapshots/`
- 保存当前 binary / core / symbol_file / 远程状态 / 最近命令 / inferior 状态
- 恢复时会优先尝试重新加载 binary、sysroot、solib 路径和远程配置，再回填缓存状态
- 恢复结果里会返回 `restore.operations`，展示每个阶段是否执行成功
- 可用于判断当前是“完全恢复”“部分恢复”还是“仅缓存恢复”

#### `gdb_capabilities`

```python
gdb_capabilities()
```

返回内容包括：

- 原始 GDB CLI 是否启用
- 原始 GDB/MI 是否启用
- pwndbg 命令是否启用
- 远程调试是否启用
- 是否只读模式

---

### 7.4 远程调试与上下文

#### `gdb_remote`

支持：

- `status`
- `connect`
- `disconnect`
- `reconnect`
- `setup`
- `set_sysroot`
- `set_solib_search_path`
- `set_remote_exec_file`
- `set_debug_file_directory`

远程连接示例：

```python
gdb_remote(
  action="connect",
  host="192.168.56.101",
  port=1234,
  mode="remote",
  local_binary="E:/ctf/pwn/pwn",
  confirm=True
)
```

扩展远程示例：

```python
gdb_remote(
  action="connect",
  host="192.168.56.101",
  port=1234,
  mode="extended-remote",
  local_binary="E:/ctf/pwn/pwn",
  remote_binary="/home/user/pwn",
  confirm=True
)
```

#### `gdb_context`

返回：

- 寄存器
- 当前指令
- 附近反汇编
- 栈内容
- backtrace
- breakpoints
- mappings
- shared libraries
- 线程与 frame 信息
- 函数参数推断

```python
gdb_context(depth=20)
```

---

### 7.5 寄存器、断点、执行控制

#### `gdb_register`

支持：

- `read_all`
- `read`
- `write`

```python
gdb_register(action="read", name="rip")
gdb_register(action="write", name="rip", value="0x401000", confirm=True)
```

#### `gdb_breakpoint`

支持：

- `list`
- `add`
- `delete`
- `enable`
- `disable`
- `condition`
- `clear`
- `watch`
- `rwatch`
- `awatch`

```python
gdb_breakpoint(action="add", location="main")
gdb_breakpoint(action="list")
```

#### `gdb_run_control`

支持：

- `run`
- `continue`
- `step`
- `next`
- `stepi`
- `nexti`
- `finish`
- `until`
- `interrupt`
- `kill`
- `restart`

```python
gdb_run_control(action="continue")
gdb_run_control(action="step", count=3)
```

---

### 7.6 原始命令、分析、ELF、插件兼容

#### `gdb_exec`

执行原始 GDB CLI 命令：

```python
gdb_exec(command="info registers")
gdb_exec(command="x/10i $rip")
```

#### `gdb_mi`

执行原始 GDB/MI 命令：

```python
gdb_mi(mi_command="-thread-info")
```

#### `gdb_analyze`

做崩溃和可利用性线索分析：

```python
gdb_analyze(mode="crash")
```

当前会输出：

- signal 推断
- fault address
- PC 是否疑似可控
- 栈中是否出现明显填充值
- backtrace 摘要
- 参数寄存器摘要
- possible causes
- `exploitation_hints.leak_hints`
- `exploitation_hints.rop_gadget_hints`
- `exploitation_hints.libc_base_guess`
- `exploitation_hints.leak_chain_suggestions`
- `exploitation_hints.strategy_hints`

这部分结果现在会尝试给出：

- 栈上疑似 libc / PIE 地址
- 当前窗口中的 gadget 分类线索，如 `ret`、`pop_rdi`、`syscall`
- 基于泄露地址的 libc 基址粗略猜测
- 常见泄露链和 ret2libc/ROP 方向提示
- 基于崩溃类型的简单利用路径建议

#### `gdb_elf`

支持：

- `checksec`
- `info`
- `entry`
- `sections`
- `segments`
- `symbols`
- `relocations`
- `dynamic`
- `got`
- `plt`
- `strings`
- `rop`
- `leaks`

```python
gdb_elf(action="checksec", path="E:/ctf/pwn/pwn")
gdb_elf(action="rop", path="E:/ctf/pwn/pwn")
gdb_elf(action="leaks", path="E:/ctf/pwn/pwn")
```

新增辅助内容：

- `rop`：从反汇编结果里提取 gadget，并附带 `category`
- `got` / `plt`：附带结构化条目解析
- `leaks`：返回常见 libc / 输出函数候选，以及常见泄露链建议
- 更适合与 `checksec`、`gdb_analyze` 联动使用

---

## 8. 典型使用流程

### 本地调试

```python
gdb_session(action="start")
gdb_load(binary="E:/ctf/pwn/pwn")
gdb_breakpoint(action="add", location="main")
gdb_run_control(action="run")
gdb_context(depth=20)
```

### 远程 gdbserver 调试

```python
gdb_session(action="start")
gdb_remote(
  action="connect",
  host="192.168.56.101",
  port=1234,
  mode="remote",
  local_binary="E:/ctf/pwn/pwn",
  confirm=True
)
gdb_breakpoint(action="add", location="main")
gdb_run_control(action="continue")
gdb_context(depth=20)
```

### 打补丁

```python
gdb_memory(action="write_block", address="0x404000", data_hex="90909090", confirm=True)
```

### 崩溃分析

```python
gdb_context(depth=32)
gdb_analyze(mode="crash")
gdb_elf(action="checksec")
```

---

## 9. 远程调试典型架构

```text
MCP Client
-> gdb-mcp
-> local GDB
-> target remote / extended-remote
-> remote gdbserver
-> target process
```

Linux 目标机安装：

```bash
sudo apt update
sudo apt install -y gdbserver gdb gcc make binutils file
```

启动：

```bash
gdbserver 0.0.0.0:1234 ./pwn
```

Windows 侧检查连通性：

```powershell
Test-NetConnection 192.168.56.101 -Port 1234
```

---

## 10. 风险控制模型

项目不是“一刀切禁止高危命令”，而是使用 **风险分级 + 二次确认**：

- `low`：直接执行
- `medium` / `high` / `critical`：第一次返回警告
- 再次调用时传 `confirm=true` 才会执行

典型受控动作：

- `target remote`
- `shell`
- `python`
- 内存写入
- dump memory
- 寄存器写入
- kill / restart

---

## 11. 测试与验证

### 11.1 smoke test

```bash
python tests/smoke_test.py
```

### 11.2 单元测试

```bash
python -m unittest tests.test_utils tests.test_gdb_controller tests.test_server_helpers tests.test_meta_tools tests.test_remote_tools tests.test_control_tools tests.test_advanced_tools
```

### 11.3 语法检查

```bash
python -m compileall server.py server_runtime.py tools_session.py tools_memory.py tools_meta.py tools_remote.py tools_control.py tools_advanced.py gdb_controller.py utils.py tests
```

---

## 12. 已知限制

- `write_block` 目前要求数值地址，不支持复杂 GDB 表达式地址。
- 块级写入依赖本地临时二进制文件与 GDB `restore` 命令。
- 某些远程场景下 `info proc mappings` 可能不可用，这会体现在结构化结果里，而不是导致整个工具失败。
- `gdb_analyze` 目前是启发式分析，不是严格 exploitability engine。
- `gdb_pwndbg` 是否真正可用，取决于本机 GDB 环境是否已安装相应插件。

---

## 13. 许可证

MIT

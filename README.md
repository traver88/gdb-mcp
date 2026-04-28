`gdb-mcp` 是一款高权限**模型上下文协议（MCP）服务端**，可让 Codex 通过 GDB/MI 接口与 `pygdbmi` 库控制 GDB 调试器。

该项目主要支持的部署架构：

```
Windows 上的 Codex
-> Windows 上的 gdb-mcp MCP 服务端
-> Windows 本地 GDB
-> target remote / target extended-remote
-> linux 虚拟机中的 gdbserver
-> 虚拟机内的目标程序
```

本服务端专为**本地授权调试、CTF Pwn 解题、崩溃分析、Core Dump 分析、漏洞利用复现、ELF 文件分析**场景设计。高风险 GDB 命令不会被永久禁用，首次执行会返回警告，调用方在重试时传入 `confirm=true` 即可运行。

------

## 工具列表

- `gdb_session`：本地 GDB 会话的启动、停止、重启与状态查询
- `gdb_load`：加载本地二进制文件、Core 文件、符号文件与启动参数
- `gdb_exec`：通用 GDB CLI 命令执行入口
- `gdb_mi`：原生 GDB/MI 命令执行入口
- `gdb_remote`：配置并连接虚拟机端 `gdbserver`
- `gdb_context`：查看寄存器、栈、反汇编、调用栈、断点、内存映射、共享库
- `gdb_memory`：内存读取、写入、搜索与转储
- `gdb_register`：寄存器读写
- `gdb_breakpoint`：普通断点、硬件断点、临时断点、观察点
- `gdb_run_control`：运行、继续、单步步入、步过、指令级单步、执行完函数、中断、杀死程序、重启
- `gdb_analyze`：崩溃与漏洞利用可行性分析
- `gdb_elf`：安全检查（checksec）、ELF 头、节、段、符号、GOT/PLT、重定位、字符串
- `gdb_pwndbg`：兼容执行 pwndbg/gef/peda 命令

所有工具返回统一 JSON 结构：

```
{
  "ok": true,
  "tool": "gdb_exec",
  "action": "exec",
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

------

## 安装

```
https://github.com/traver88/gdb-mcp.git
```

本项目支持的运行环境为 **Python 3.12**。

### Windows 环境：Codex + Windows gdb-mcp + 虚拟机 gdbserver

#### 在项目目录安装 Python隔离环境

```
python --version
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .
```

#### Windows：安装 GDB

##### 方式 A：MSYS2 MinGW64 GDB

1. 安装 MSYS2
2. 打开 MSYS2 MinGW64 终端
3. 执行：

```
pacman -Syu  # 之后重启 MSYS2
pacman -S gdb gdb-multiarch
```

1. 将 `C:\msys64\mingw64\bin` 加入 Windows `PATH`
2. 验证：

```
gdb --version
gdb-multiarch --version
```

#### 运行smoke_test测试

```
gdb-mcp项目目录下：
.\.venv\Scripts\activate
python tests\smoke_test.py
```

成功会输出：

```
smoke test passed
```

smoke_test.py测试内容：

- 启动 Windows 本地 GDB
- 加载 `examples/hello.c` 编译的测试程序
- 在 `main` 下断点
- 运行程序
- 读取寄存器
- 读取栈
- 反汇编
- 关闭 GDB

------

## 虚拟机（Ubuntu/Kali）配置

### 安装 gdbserver

```
sudo apt update
sudo apt install -y gdbserver gdb gcc make binutils file
```

### 启动目标程序

```
cd xxx/xxx/
gdbserver 0.0.0.0:1234 ./pwn
```

### Windows 端连通性测试

powershell:

```
ping 192.168.56.101
Test-NetConnection 192.168.56.101 -Port 1234
```

------

## Codex 配置 config.toml

```
[mcp_servers.gdb-mcp]
command = "D:\\gdb-mcp\\.venv\\Scripts\\python.exe"
args = ["D:\\gdb-mcp\\server.py"]
```

- `command`：指向启动 MCP 服务端的 Python 程序
- `args`：指向 `server.py` 服务端入口

------

## Codex 使用示例

需求示例：

```
请使用 gdb-mcp：
- 启动 GDB
- 加载本地符号文件 E:/ctf/pwn/pwn
- 连接 192.168.56.101:1234 的 gdbserver
- 在 main 下断点
- continue
- 显示寄存器、栈、RIP 附近反汇编、backtrace
```

等价 MCP 调用：

```
gdb_session(action="start")
gdb_remote(
  action="connect",
  host="192.168.56.101",
  port=1234,
  mode="remote",
  local_binary="E:/ctf/pwn/pwn",
  confirm=true
)
gdb_breakpoint(action="add", location="main")
gdb_run_control(action="continue")
gdb_register(action="read_all")
gdb_memory(action="read", address="$rsp", size=160)
gdb_exec(command="x/20i $rip")
gdb_exec(command="bt")
gdb_context(depth=20)
```

等价 GDB 命令：

```
file "E:/ctf/pwn/pwn"
target remote 192.168.56.101:1234
b main
c
info registers
x/20gx $rsp
x/20i $rip
bt
```

------

## 扩展远程模式（Extended remote）

虚拟机：

```
gdbserver --multi 0.0.0.0:1234
```

MCP 调用：

```
gdb_remote(
  action="connect",
  host="192.168.56.101",
  port=1234,
  mode="extended-remote",
  local_binary="E:/ctf/pwn/pwn",
  remote_binary="/xxx/pwn",
  confirm=true
)
gdb_breakpoint(action="add", location="main")
gdb_run_control(action="run")
gdb_context(depth=20)
```

内部 GDB 命令：

```
file "E:/ctf/pwn/pwn"
set remote exec-file /xxx/pwn
target extended-remote 192.168.56.101:1234
```

------

## 常见问题

- Windows 无法 ping 通虚拟机：检查虚拟机 IP 与网卡模式
- 1234 端口无法连接：确认 `gdbserver` 正在运行
- `gdbserver` 仅监听本地：使用 `gdbserver 0.0.0.0:1234 ./pwn`
- Windows 防火墙拦截：放行 GDB 或对应端口
- 虚拟机 NAT 模式无法访问：改用仅主机 / 桥接网卡或配置端口转发
- `local_binary` 与 `remote_binary` 混淆：前者为 Windows 路径，后者为 Linux 路径
- Windows GDB 无法解析 Linux ELF：使用对应架构的多架构 GDB
- 远程模式下 `info proc mappings` 不可用：`gdb_context` 会标记为不可用而非崩溃
- 远程 libc 符号缺失：使用 `gdb_remote(action="set_sysroot", ...)` 或 `set_solib_search_path`

------

## 风险操作确认

需确认的高风险命令示例：

- `target remote HOST:PORT`
- `target extended-remote HOST:PORT`
- `disconnect`
- `detach`
- `set remote exec-file PATH`
- `set sysroot PATH`
- `set solib-search-path PATH`
- `shell ...`
- `source ...`
- `python ...`
- `dump memory ...`
- `restore ...`
- `maintenance ...`

首次调用：

```
gdb_exec(command="target remote 192.168.56.101:1234")
```

服务端返回 `need_confirm=true`，带确认重试：

```
gdb_exec(command="target remote 192.168.56.101:1234", confirm=true)
```

执行后返回中 `executed_with_risk=true`。

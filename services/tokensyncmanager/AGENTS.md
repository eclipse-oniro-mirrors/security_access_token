# TokenSyncManager Service

## 核心职责

在可信设备间同步权限授予状态。当权限状态变更时（授予/撤销或应用更新），TokenSyncManager 将变更传播到可信设备，确保分布式系统中的权限执行一致。

## 知识索引

改动前按场景读取对应文件或查看代码：

| 场景 | 先读 |
| --- | --- |
| 协议字段或版本变更 | `include/protocol`、`include/command`、`include/remote`、序列化辅助函数 |
| 远程命令行为变更 | `include/command`、`src/command`、`include/remote/remote_command_factory.h` |
| 设备上线/离线或通信生命周期 | `include/remote/soft_bus_manager.h`、`include/remote/soft_bus_channel.h`、`include/device`、`RemoteCommandManager` |
| 设备 ID 转换或身份处理 | `include/device`、`include/remote/soft_bus_manager.h` |
| IPC 或服务入口行为 | `include/service`、service stub、远程 accesstoken 调用点 |

## 项目约束

### 关键不变量
- **命令生命周期**：Prepare()（请求方）→ Execute()（响应方）→ Finish()（请求方处理响应）
- **设备 ID 类型**：`networkId`（动态连接ID）、`UUID`（持久唯一ID）、`UDID`（设备管理ID）
- **命令缓冲**：设备离线时命令缓冲，上线时顺序执行
- **版本兼容性**：必须保证新旧版本设备间通信兼容

### 禁止改动（需显式审查）
- 不改变协议字段含义、版本协商含义、命令负载结构
- 不删除旧版本设备可能需要的协议字段（保持可读性直到明确计划废弃）
- 不改变设备 ID 转换规则（`networkId` ↔ `UUID` ↔ `UDID`）
- 不改变命令顺序、缓冲、上线/离线重试假设

### RPC 通信格式兼容性
**关键原则**：修改 RPC 通信格式必须保证新旧版本设备间的兼容性

**兼容场景处理**：
| 场景 | 策略 |
| --- | --- |
| 旧 → 新 | 新设备必须处理旧版本格式 |
| 新 → 旧 | 新设备必须发送旧兼容格式 |
| 旧 → 旧 | 保持原格式 |
| 新 → 新 | 使用新格式 |

**兼容性设计原则**：
1. **仅增量变更**：新字段必须可选，使用前检查存在性
2. **不删除字段**：废弃字段必须保留，可添加替换字段

### 常见陷阱
- 只改 JSON 序列化而不检查反序列化和命令工厂创建逻辑
- 只改本地请求方路径而不检查远程响应方路径和响应处理路径
- 只改协议版本常量而不定义混合版本对等行为

## 核心组件速查

- **TokenSyncManagerService**：系统能力入口，提供 IPC 接口
- **RemoteCommandManager**：中央管理器，维护每设备 `RemoteCommandExecutor` 实例
- **RemoteCommandExecutor**：每设备命令执行器，支持命令缓冲和通道管理
- **BaseRemoteCommand**：所有远程命令的抽象基类，实现命令模式
- **SoftBusManager**：管理 SoftBus 服务绑定和设备连接
- **DeviceInfoManager**：管理在线和本地设备的缓存信息
- **RemoteProtocol**：远程命令通信的协议数据结构

## 完成定义

改动必须满足：
- 构建受影响的服务目标
- 说明协议兼容性、版本行为、设备身份处理是否变化
- 报告验证的混合版本或运行时设备场景，未验证的兼容性风险

# PrivacyManager Service

## 核心职责

管理权限使用记录和活跃状态（应用是否正在使用权限）。

## 知识索引

改动前按场景读取对应文件或查看代码：

| 场景 | 先读 |
| --- | --- |
| 使用记录增删改查 | `include/record`、`src/record`、`include/database`、`src/database` |
| 活跃状态启停流程 | `include/record/permission_record_manager.h`、`include/active`、`src/active` |
| 禁用/静默策略 | `include/disable_policy`、`include/sensitive`、`src/disable_policy`、`src/sensitive` |
| IPC 接口或回调契约 | `include/service`、service stub/proxy、framework Parcel 类型 |
| 数据库 schema 或保留逻辑 | `include/database`、DB 初始化或迁移代码、记录清理代码 |
| 新增权限记录支持 | `include/common/constant.h`、`src/common/constant.cpp` |

## 项目约束

### 高风险路径
- **AddPermissionUsedRecord**：频繁调用，使用内存缓存（`permUsedRecList_`）批量写库，避免阻塞调用者
- **StartUsingPermission**：应用开始使用敏感权限时调用，快速检查静默/禁用策略/锁屏状态，避免阻塞操作
- **IsAllowedUsingPermission**：频繁验证权限使用是否允许，先检查内存缓存（静默状态、禁用策略），最小化 DB 查询

### 关键不变量
- **内存-数据库一致性**：内存缓存（`permUsedRecList_`）必须与持久化存储同步，使用 `needUpdateToDb` 标志追踪脏记录
- **数据库事务**：多步操作使用事务保证原子性，失败时实现回滚机制


### 禁止改动（需显式审查）
- 不改变 `AddPermissionUsedRecord`、`StartUsingPermission`、`StopUsingPermission`、`IsAllowedUsingPermission` 或回调注册接口的语义
- 不改变回调触发时机、回调过滤规则、回调负载含义
- 不改变静默策略优先级（EDM > Privacy > Temporary）、禁用策略执行顺序、锁屏检查
- 新增 `user_grant` 权限时必须同时更新 `OpCode` 枚举和 `PERMISSION_OPCODE_MAP`，已有权限和`OpCode`映射不能修改，数据库进行了持久化

### 常见陷阱
- 只改数据库写路径而不检查内存缓存、脏标志处理、清理任务
- 只改回调管理器而不检查服务注册/注销路径和活跃状态触发路径
- 只改权限名而不更新 opCode 映射和验证路径
- 优化高频路径时跳过验证、权限检查或状态同步


## 完成定义

改动必须满足：
- 构建受影响的服务目标
- 说明使用记录语义、活跃状态语义、回调行为、保留行为是否变化
- 报告验证的回调或 IPC 路径

# AccessTokenManager Service

## 核心职责

管理权限授予状态（应用是否拥有权限：granted/denied）和授予模式（system_grant/user_grant）。

## 知识索引

改动前按场景读取对应文件或查看代码：

| 场景 | 先读 |
| --- | --- |
| 四阶段安装/更新流程 | `InstallSessionManager`、`AccessTokenManagerService`、`PermissionManager`、`AccessTokenInfoManager` |
| 权限验证高频路径 | `PermissionDataBrief`、`PermissionManager`、`VerifyAccessToken` |
| TokenID/UID 分配 | `AccessTokenIDManager`、`AccessTokenInfoManager`、迁移或保留 token 逻辑 |
| 权限状态持久化 | `database/`、`DataTranslator`、`PermissionManager`、`AccessTokenInfoManager` |
| 权限定义 | `frameworks/common/*/permission_map.*`、`frameworks/common/*.py`、`PermissionManager` |
| IPC/IDL/Parcel | `include/service`、idl、framework Parcel 类、客户端/代理/存根调用路径 |
| 迁移或保留token 行为 | `AccessTokenMigrationManager`、`InstallSessionManager`、`AccessTokenIDManager` |
| 保留/非信任应用 | 检查 token 集合成员关系、缓存所有权、持久化更新 |
| 权限定义访问模式 | 使用 `permission_map.h` 的 `GetPermissionBriefDef()`，不查库 |
| 数据一致性保证 | 必须遵循：Kernel → Database → Cache 顺序 |

## 项目约束

### 高风险路径
- **VerifyAccessToken**：高频调用，禁止增加 DB 查询或阻塞操作
- **四阶段安装流程**：必须检查全部四个阶段，不能孤立修改某一阶段
- **权限定义访问**：必须从 `permission_map.h` 获取，不能查 `permission_definition_table`
- **DB 存储权限名**：存储 `permission_name`（字符串）而非 `perm_code`（整数），因为映射不稳定

### 关键不变量
- **TokenID 集合互斥**：每个 TokenID 只能属于 `tokenIdSet_`、`reservedTokenIdSet_`、`untrustedTokenIdSet_` 之一
- **UID 唯一性**：不同应用不能共享 UID，每个 UID 映射到一个 bundleId
- **数据一致性顺序**：Kernel → Database → Cache，失败时需回滚
- **缓存生命周期**：活跃应用常驻内存，非活跃应用按需加载/释放

### 禁止改动（需显式审查）
- 不改变四阶段安装流程的原子性或回滚规则
- 不改变权限继承规则（`UpdatePermStatus` 逻辑）
- 不改变保留 token 类型的行为（`RESERVED_IDENTITY` / `RESERVED_DATA`）
- 不改变 ACL/EDM 检查规则或优先级
- 不改变 IDL/Parcel 字段顺序或序列化格式

### 常见陷阱
- 只改数据库持久化而不检查缓存初始化、刷新、回滚、启动恢复
- 只改某一阶段安装流程而不检查其它阶段的依赖
- 改权限定义而只更新枚举不更新映射，或反之
- 优化高频路径时跳过验证、权限检查或状态同步
- 查询权限定义表而非使用 `permission_map.h`

## 完成定义

改动必须满足：
- 构建受影响的服务目标
- 说明权限语义、安装流程、token 生命周期或持久化行为是否变化
- 报告验证的内核、迁移、安装会话场景，未验证的风险

## 关键流程速查

### 四阶段安装流程
1. **CheckHapSignInfo**：验证签名，创建会话
2. **CheckHapPermissionInfo**：检查权限列表（ACL/EDM），初始化状态
3. **PrepareHapIdentity**：分配 TokenID 和 UID，处理保留 token
4. **FinishInstall**：写库、通知 SPM、清理会话

### 权限验证路径
```
Client Process → Kernel Cache (fast)
→ VerifyAccessToken (IPC) → PermissionDataBrief → Result
```

### 数据一致性保证
```
1. Kernel → 2. Database → 3. Cache
失败时回滚已完成的步骤
```

## 相关模块

| 模块 | 职责 |
| --- | --- |
| AccessTokenManager | 权限授予状态（HAS permission?） |
| PrivacyManager | 权限使用记录/状态（USING permission?） |
| TokenSyncManager | 分布式权限同步 |
| SPM | 内核权限执行（FinishInstall 后） |

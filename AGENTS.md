# AGENTS.md

## 项目定位

本仓库对应 OpenHarmony `base/security/access_token`，提供统一的访问令牌权限管理，控制应用对敏感数据和 API 的访问权限。优先按这些目录定位问题：

- `services/`：AccessTokenManager（权限授予状态）、PrivacyManager（权限使用状态）、TokenSyncManager（分布式权限同步）、El5FileKeyManager（锁屏文件加密）
- `interfaces/`：内部接口（`innerkits`）、外部接口（`kits/capi`、`kits/cj`、`kits/js`）
- `frameworks/`：IPC 序列化、公共组件（`frameworks/common`）、JSON 适配（`frameworks/json_adapter`）、NAPI/ANI绑定
- `services/common/`：数据库、DFX等基础结构
- `config/`、`tools/`：构建配置与开发工具
- `test/`、`test/fuzztest/`：单元测试和 fuzz 目标

## 核心职责划分

| 组件 | 职责 |
| --- | --- |
| AccessTokenManager | 管理权限授予状态（应用是否拥有权限），提供权限验证、授权、撤销、状态订阅 |
| PrivacyManager | 管理权限使用状态（应用是否正在使用权限），提供使用记录、活跃状态、状态订阅 |
| TokenSyncManager | 在可信设备间同步权限状态，支持分布式权限验证 |
| El5FileKeyManager | 提供锁屏文件加密的密钥管理服务 |
| Frameworks Common | 共享工具、LOGC 日志、HiSysEvent 上报、数据验证、权限映射 |
| 工具、测试辅助 | 开发工具和测试辅助脚本 |

## 改动前确认

改动前必须明确：

1. **任务类别**：权限授予状态、权限使用状态、分布式同步、锁屏加密、IPC、数据库、JS/ETS 绑定、DFX、安全审查或其它
2. **已读文档**：列出相关的 AGENTS.md、源码文件或设计文档
3. **适用约束**：列出本次改动必须遵守的约束项（高频路径、数据一致性、接口兼容性、安全、架构依赖、并发重入、编码规范等）

## 知识索引

改动前按场景读取对应文件或查看代码：

| 场景 | 先读 |
| --- | --- |
| 权限授予状态、Token 生命周期、权限验证 | `services/accesstokenmanager/AGENTS.md` |
| 权限使用记录、活跃状态、隐私开关 | `services/privacymanager/AGENTS.md` |
| 分布式权限同步、设备间权限验证 | `services/tokensyncmanager/AGENTS.md` |
| 锁屏文件加密、密钥管理 | 探索 `services/el5filekeymanager/`  |
| 工具、测试辅助 | 探索 `tools/` |
| LOGC 日志、HiSysEvent、DFX | `frameworks/common/AGENTS.md` |
| IPC 序列化、IDL、Parcel 字段、事务码 | `frameworks/accesstoken`、`frameworks/privacy`、`services/accesstokenmanager/idl`、`services/privacymanager/idl`；改动前追踪 client → proxy/stub → service 完整路径，核对所有调用点 |
| JS/ETS/NAPI/ANI 绑定、`kits/js`、`kits/capi`、`kits/cj` | `interfaces/kits/` 下的 API 声明与 `frameworks/js/napi`、`frameworks/ets/ani` 的原生实现必须一致 |
| 数据库或持久化改动 | 追踪内存缓存更新路径后再改 schema 或存储值 |
| 公共工具、权限映射 | `frameworks/common/AGENTS.md`，检查所有服务和 SDK 调用点后再改公共组件 |

## 构建和验证

构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```bash
# 构建功能代码
./build.sh --product-name rk3568 --build-target access_token

# 构建单元测试
./build.sh --product-name rk3568 --build-target base/security/access_token:accesstoken_build_module_test

# 构建 fuzz 测试
./build.sh --product-name rk3568 --build-target base/security/access_token:accesstoken_build_fuzz_test --gn-args use_cfi=false use_thin_lto=false

# 独立编译（功能代码）
hb build access_token -i

# 独立编译（测试用例）
hb build access_token -t --gn-args use_cfi=false use_thin_lto=false

# 运行单元测试
run -t UT -tp access_token

# 运行 fuzz 测试
run -t FUZZ -tp access_token

# 静态分析（如可用）
./build.sh --product-name rk3568 --build-target access_token --gn-args enable_cpp_static_check=true
```

## 项目约束

### 高频路径与性能约束

- **权限验证高频路径**（`VerifyAccessToken`）：每次权限校验都会调用，禁止增加阻塞 I/O、数据库查询或复杂迭代
- **权限使用记录写入**（`AddPermissionUsedRecord`）：应用使用敏感权限时触发，数据库写入禁止阻塞调用方，优先批量持久化
- **权限使用开始**（`StartUsingPermission`）：应用启动功能时调用，禁止阻塞操作延迟应用启动或功能接入
- **SA 初始化**禁止耗时操作，必须保证不失败

### 数据一致性与持久化约束

- **数据库操作**必须保持内存与持久化状态一致，失败时需回滚到一致状态
- **Token、权限、记录的更新**优先使用原地更新或原子替换，避免破坏性的中间状态。对于 token、权限、记录或数据库更新流程，优先使用就地更新或原子替换而非删除重建模式。如果必须重建，需保持原始有效状态可恢复，直到新状态完全提交，并确保回滚恢复完整的更新前状态

### 接口兼容性约束

- **IPC 序列化、IDL、Parcel 字段**改动必须检查所有客户端、proxy、stub、服务调用的兼容性
- **公共 API、SDK、JS/ETS 接口**改动必须保证向后兼容
- **事务码、字段顺序、存储格式**等跨版本兼容性问题需检查所有调用点

### 安全约束

- 禁止绕过权限检查、信任检查、设备信任假设、跨用户隔离规则

### DFX 与可观测性约束

- **LOGC 使用**：仅用于致命验证失败，禁止用于统计、调试或预期错误（参考 `frameworks/common/AGENTS.md`）
- **HiSysEvent 上报**：遵循事件类型定义，禁止滥用 FAULT 类型上报
- **日志规范**：遵循 OpenHarmony 日志规范，禁止泄露敏感信息

### 架构与依赖约束

- **权限授予状态**（AccessTokenManager）与**权限使用状态**（PrivacyManager）职责分离，不要混淆
- **依赖方向**保持单向：`interfaces` ← `frameworks` ← `services`，避免循环依赖

### 并发与重入约束

- 禁止持有锁时调用可能重入当前模块的同步回调、IPC 请求或跨模块通知
- 限制锁范围到本地状态更新，在解锁前捕获通知数据，在锁释放后执行外部回调

### 编码规范约束

- **C++ 改动**遵循 OpenHarmony 编码规范：不混用有符号/无符号类型，行宽 ≤120 字符，函数 ≤50 行
- 目录之间不要出现循环依赖

## 完成定义

改动必须满足：
- 构建受影响的目标代码，或明确说明无法构建的原因
- 保持 API、IPC、持久化、权限语义兼容（除非任务明确要求改动）
- 运行对应的单元测试和 fuzz 测试
- 说明运行的命令、结果、跳过的验证及剩余风险

## 最终响应要求

任务完成时报告：

1. **修改清单**：修改的文件列表和关键变更点
2. **构建结果**：运行的构建命令和结果（成功/失败）
3. **测试结果**：运行的测试命令和结果（通过/失败）
4. **影响评估**：兼容性影响评估（API、IPC、持久化、权限语义）
5. **风险说明**：未验证的场景和剩余风险
6. **替代方案**：如果无法运行验证，说明原因并提供替代验证方案

## 常见陷阱

- 只改 `.idl` 或 Parcel 而不检查对应的代理、stub、服务、客户端、测试
- 只改数据库持久化而不检查缓存初始化、刷新、回滚、启动恢复路径
- 优化高频路径时跳过验证、权限检查或状态同步
- 持有锁时调用可能重入当前模块的同步回调、IPC 请求或跨模块通知

## 历史记录
| version | date | modify content | writer |
|------|------|---------|--------|
| v1.0 | 2026-01-31 | primary version | xiacong |
| v1.1 | 2026-02-05 | clarify distinction between Permission Grant State (AccessTokenManager) and Permission Usage Status (PrivacyManager) | hehehe-li |
| v1.2 | 2026-07-10 | add task routing, high-risk boundaries, and validation loop guidance for coding agents | xiacong, AI |
| v1.3 | 2026-07-14 | add repository-wide lock callback safety and update-state consistency constraints | linshuqing, AI |
| v2.0 | 2026-07-23 | simplify by removing code-explorable knowledge, keep only constraints and routing guidance | hehehe-li, AI |
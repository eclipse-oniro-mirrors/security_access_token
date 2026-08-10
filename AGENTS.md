# AGENTS.md

## 项目定位

本仓库对应 OpenHarmony `base/security/access_token`，提供统一的访问令牌权限管理，控制应用对敏感数据和 API 的访问权限。优先按这些目录定位问题：

- `services/`：AccessTokenManager（权限授予状态，高频路径 `VerifyAccessToken`）、PrivacyManager（权限使用状态，高频路径 `AddPermissionUsedRecord`/`StartUsingPermission`）、TokenSyncManager（分布式权限同步，协议兼容性敏感）、El5FileKeyManager（锁屏文件加密）
- `interfaces/`：内部接口（`innerkits`）、外部接口（`kits/capi`、`kits/cj`、`kits/js`）；公共 API 改动需向后兼容
- `frameworks/`：IPC 序列化（事务码/Parcel 字段跨版本敏感）、公共组件（`frameworks/common`，改动需检查全部服务和 SDK 调用点）、JSON 适配（`frameworks/json_adapter`）、NAPI/ANI绑定
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
3. **将加载的技能**：按下方「技能调用」表匹配本次任务对应的 ohos-* 技能并加载；无匹配项时显式声明"无"，不得静默跳过
4. **适用约束**：列出本次改动必须遵守的约束项（高频路径、数据一致性、接口兼容性、安全、架构依赖、并发重入、编码规范等）

## 知识索引

改动前按场景读取对应文件或查看代码：

| 场景 | 先读 |
| --- | --- |
| 权限授予状态、Token 生命周期、权限验证 | `services/accesstokenmanager/AGENTS.md` |
| 权限使用记录、活跃状态、隐私开关 | `services/privacymanager/AGENTS.md` |
| 分布式权限同步、设备间权限验证 | `services/tokensyncmanager/AGENTS.md` |
| 锁屏文件加密、密钥管理 | 探索 `services/el5filekeymanager/` |
| 工具、测试辅助 | 探索 `tools/` |
| LOGC 日志、HiSysEvent、DFX | `frameworks/common/AGENTS.md` |
| IPC 序列化、IDL、Parcel 字段、事务码 | `frameworks/accesstoken`、`frameworks/privacy`、`services/accesstokenmanager/idl`、`services/privacymanager/idl`；改动前追踪 client → proxy/stub → service 完整路径，核对所有调用点 |
| JS/ETS/NAPI/ANI 绑定、`kits/js`、`kits/capi`、`kits/cj` | `interfaces/kits/` 下的 API 声明与 `frameworks/js/napi`、`frameworks/ets/ani` 的原生实现必须一致 |
| 数据库或持久化改动 | 追踪内存缓存更新路径后再改 schema 或存储值 |
| 公共工具、权限映射 | `frameworks/common/AGENTS.md`，检查所有服务和 SDK 调用点后再改公共组件 |
| 日志/issue 出现 `LOGC`、`HiSysEvent` | `frameworks/common/AGENTS.md`（DFX 事件定义与上报时机） |
| 代码出现 `*Stub`/`*Proxy`（生成文件） | `services/*/idl/*.idl` 是生成源，禁止手改生成产物 |

## 技能调用

改动前必须按下表匹配并加载对应 ohos-* 技能；无匹配项时在「改动前确认」第 3 项中显式声明"无"。按场景选用：

### 开发与规范

| 场景 | 推荐技能 | 触发时机 |
| --- | --- | --- |
| 编写/修改/审查 OpenHarmony C 或 C++ 代码 | `ohos-dev-cpp-coding-style` | 任何 `.c/.cpp/.h` 改动，或涉及 C/C++ 命名、所有权、继承、lambda 捕获、注释规范 |
| 新建/迁移/修改 SystemAbility（IDL、Proxy/Stub、SA 注册、CFG、SELinux） | `ohos-dev-sa-codegen` | 改动 `.idl` 或 `services/*/idl`、新增 SA 接口、迁移手写 Proxy/Stub 到 IDL 模式 |
| NAPI/ANI 原生绑定开发、移植、审查 | `ohos-dev-napi-module` | 改动 `frameworks/js/napi`、`frameworks/ets/ani`，或 `napi_module` 注册、异步工作 |
| ArkTS 静态语义/类型系统疑问 | `ohos-dev-arkts-static-specification-reference` | 排查 `kits/js`、`kits/cj` 声明中的 ArkTS 编译期语义 |

### 安全审查（本仓库为权限核心，优先级高）

| 场景 | 推荐技能 | 触发时机 |
| --- | --- | --- |
| C++ 系统服务安全审查 | `ohos-dev-security-code-review` | 改动 IPC Stub/`OnRemoteRequest` 授权、MessageParcel/fd/回调校验、AccessToken 权限检查、跨用户/账户/设备隔离、隐私日志泄露、共享状态竞态后必须用此技能审查 |

### 接口设计检视

| 场景 | 推荐技能 | 触发时机 |
| --- | --- | --- |
| C API（`.h`）接口设计规范检视 | `ohos-design-c-api-review` | 改动 `interfaces/kits/capi` 声明 |
| ArkTS/ETS API 接口设计规范检视 | `ohos-design-arkts-api-review` | 改动 `interfaces/kits/js`、`interfaces/kits/cj` 声明 |
| API 文档与接口声明/实现一致性检查 | `ohos-dev-chinese-docs-review` | 公共 API 文档或错误码文档改动 |

### 构建与测试

| 场景 | 推荐技能 | 触发时机 |
| --- | --- | --- |
| OpenHarmony 构建执行/诊断 | `ohos-dev-build-execution-diagnosis` | 全量/部件独立编译、测试构建失败、`build.log` 分析 |
| 生成 C/C++ 单元测试（HWTEST/ohos_unittest） | `ohos-test-ut-generation` | `test/` 补充单元测试用例 |
| 生成 LLVM libFuzzer FUZZ 用例并做安全规范审查 | `ohos-test-fuzz-generation` | `test/fuzztest/` 补充或新增 fuzz 目标 |
| 设备端验证（hdc 日志/安装/remount 等） | `ohos-dev-hdc-command-usage` | 需在真机/模拟器验证权限授予、使用记录、分布式同步行为 |

### 工作流

| 场景 | 推荐技能 | 触发时机 |
| --- | --- | --- |
| PR CI 状态调查（DCP 事件、构建标签、CI 日志） | `ohos-ci-openharmony-ci-analysis` | PR 提交后排查 CI 失败 |
| GitCode PR 审查（oh-gc 获取 PR 元数据/diff/评论） | `ohos-dev-gitcode-pr-review` | 提交或审查 PR |
| 审计本文件等仓库代理指导质量 | `ohos-design-agent-instruction-quality-review` | 维护/改进本 AGENTS.md 或其它 coding-agent 指导文件 |

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
- **数据库升级**必须保证升级后的表结构与初始建表结果等价，避免升级路径遗漏字段、索引、主键或默认值导致与安装不一致
- **Token、权限、记录的更新**优先使用原地更新或原子替换，避免破坏性的中间状态。对于 token、权限、记录或数据库更新流程，优先使用就地更新或原子替换而非删除重建模式。如果必须重建，需保持原始有效状态可恢复，直到新状态完全提交，并确保回滚恢复完整的更新前状态

### 接口兼容性约束

- **IPC 序列化、IDL、Parcel 字段**改动必须检查所有客户端、proxy、stub、服务调用的兼容性
- **公共 API、SDK、JS/ETS 接口**改动必须保证向后兼容
- **事务码、字段顺序、存储格式**等跨版本兼容性问题需检查所有调用点

### 安全约束

- 禁止绕过权限检查、信任检查、设备信任假设、跨用户隔离规则

### 需显式审查/升级（Ask before）

以下改动属于高影响范围，必须在动手前声明并寻求人工审查，不可自行决策：

- 修改权限校验逻辑、授权/撤销判定、信任规则或保留 token 类型行为
- 修改跨用户、跨账户、跨设备隔离规则或设备信任假设
- 修改事务码、IDL/Parcel 字段顺序、序列化格式或数据库存储值（跨版本兼容性敏感）
- 修改公共 API 签名、错误码、生命周期语义或 JS/ETS/C API 声明
- 修改 LOGC/HiSysEvent 事件定义或上报时机（影响故障归因）

### DFX 与可观测性约束

- **LOGC 使用**：仅用于致命验证失败，禁止用于统计、调试或预期错误（参考 `frameworks/common/AGENTS.md`）
- **HiSysEvent 上报**：遵循事件类型定义，禁止滥用 FAULT 类型上报
- **日志规范**：遵循 OpenHarmony 日志规范，禁止泄露敏感信息

### 架构与依赖约束

- **权限授予状态**（AccessTokenManager）与**权限使用状态**（PrivacyManager）职责分离，不要混淆
- **依赖方向**保持单向：`interfaces` ← `frameworks` ← `services`，避免循环依赖
- **生成代码边界**：`services/*/idl/*.idl` 是 Proxy/Stub 的生成源（`idl_gen_interface`），生成产物在 `${target_gen_dir}`；禁止手改生成的 `*_proxy.cpp`/`*_stub.cpp`，改 `.idl` 后重新生成
- 既有外部查询接口的返回值语义必须保持兼容；如果内部新增更细粒度或平台相关错误码，不能直接对外透传，历史上返回 `ERR_TOKENID_NOT_EXIST` 的非法或不可解析 TokenID 场景仍应保持该错误码，除非经过兼容性评审明确允许变更

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

0. **技能加载回执**：实际调用了哪些 ohos-* 技能（skill 名），或声明"未加载"及原因
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
| v2.1 | 2026-07-28 | clarify that existing external query interfaces must preserve compatible return-code semantics | linshuqing, AI |
| v2.2 | 2026-08-10 | add explicit ohos-* skill invocation recommendations mapped to repo scenarios, annotate high-risk paths in code map, add ask-before escalation list | hehehe-li, AI |
| v2.3 | 2026-08-12 | promote skill invocation from advisory to mandatory: add skill declaration to pre-edit checklist, add skill receipt to final response, widen C++ skill trigger to cover .c files | hehehe-li, AI |
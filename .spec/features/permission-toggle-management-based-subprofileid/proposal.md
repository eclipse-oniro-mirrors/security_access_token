# 需求文档

> 一份文档，从原始需求到基线结论。按阶段追加内容，不拆成多份独立文件。

## 一、原始需求

### 基本信息

| 字段 | 内容 |
|------|------|
| 需求ID | permission-toggle-management-based-subprofileid |
| 需求名称 | 基于 `subProfileId` 的 permission toggle 管理 |
| 来源 | 需求澄清会话 |
| 提出人 | 当前会话需求方 |
| 目标发行版本 | master |
| 候选 Profile | none |
| 优先级 | P1 |
| 状态 | Clarifying |

### 原始描述

**原始问题：** 当前权限弹框开关和权限使用记录开关基于 userId 生效；手机/PC 场景中一个 userId 对应一个主 profile，但车机场景中一个 userId 可对应多个 `subProfileId`。当前能力不支持车机，需要引入 `subProfileId` 管理。

**痛点：**

| 用户类型 | 当前痛点 | 影响 |
|----------|----------|------|
| 车机系统开发者 | 同一 `userId` 下多个 `subProfileId` 无法独立配置开关 | 配置粒度不足，导致开关状态串扰 |
| 车机最终用户 | 不同子档案之间无法隔离权限弹框与权限使用记录策略 | 隐私与使用体验不符合预期 |

**期望结果：** 与开关相关的能力在车机场景可按 `subProfileId` 生效，同时对单 profile 的手机/PC 场景保持兼容。

### 背景证据

| 证据类型 | 链接/路径 | 说明 |
|----------|-----------|------|
| 需求输入 | 当前会话 | 用户给出接口清单、现状和目标 |
| 源码核对 | `services/accesstokenmanager`、`services/privacymanager`、`interfaces/innerkits/*`、`frameworks/js|ets/*` | 已确认现有接口主链路以 `userId` 为输入 |

### 初始范围

**可能包含：**
- 权限弹框开关 InnerKit 接口入参语义调整或新增接口
- 权限使用记录开关 InnerKit 接口入参语义调整或新增接口
- JS/ETS API 行为或映射调整
- AccessTokenManager/PrivacyManager 服务侧持久化键与查询维度调整
- 车机 `subProfileId` 维度的存储与查询规则引入

**明确不包含：**
- 与开关无关的权限校验主流程
- 分布式 token sync 能力
- 新增权限类型或权限定义

### 初始假设

| 假设 | 类型 | 验证方式 | 状态 |
|------|------|----------|------|
| 本次需求仅覆盖两个“开关”能力，不扩展其他以 userId 维度存储的权限能力 | 业务 | Owner 确认 | 待验证 |
| 本需求统一使用 `subProfileId` 术语，不再引入 `accountId` 概念 | 技术 | Owner 确认 | 已验证 |
| JS API 通过新增接口显式支持 `subProfileId`，旧 API 保持原行为 | 兼容性 | Owner 确认 | 已验证 |
| 手机/PC 单 profile 场景需要保持旧行为兼容 | 兼容性 | Owner 确认 | 已验证 |

### 初始分级判断

| 判断项 | 结果 | 依据 |
|--------|------|------|
| 复杂度 | 标准 | 跨 ATM/Privacy 两条服务链路，涉及 InnerKit 与 JS/ETS API 行为 |
| 涉及仓数量 | 1 | 当前仓 `base/security/access_token` |
| 是否涉及 Public/System API | 是 | JS/ETS API 对外行为可能受影响 |
| 是否涉及安全/性能关键路径 | 是 | 涉及权限/隐私开关存储和查询维度 |
| 是否跨 SIG | 待确认 | 车机 `subProfileId` 语义可能需外部 owner 对齐 |

### 进入澄清条件

- [x] 原始问题和期望结果已记录
- [x] 初始范围和不包含项已记录
- [x] 关键假设和待澄清问题已列出
- [x] 复杂度有判断或明确为待定
- [x] 需求来源和责任人已明确

---

## 二、澄清记录

### 待澄清问题

| 编号 | 问题 | 为什么需要澄清 | 状态 |
|------|------|----------------|------|
| Q-1 | InnerKit 接口是“直接把 `userId` 参数语义改成 `subProfileId`”，还是“保留 `userId` 语义并新增 `subProfileId` 入参”？ | 这决定 API 兼容策略和 design/spec 范围 | 已澄清 |
| Q-2 | JS/ETS API 是否通过新增接口显式传入 `subProfileId`，还是必须保持现有无参签名并从上下文获取？ | 这决定 System API 扩展方式 | 已澄清 |
| Q-3 | 读取/设置开关时，是否统一以 `subProfileId` 作为新维度主键？ | 这决定数据模型与持久化主键 | 已澄清 |
| Q-4 | 旧有按 `userId` 存量数据如何兼容：是否允许直接继承、何时清理旧数据、何时报错阻止按 `subProfileId` 设置？ | 这决定迁移策略与边界场景 AC | 已澄清 |
| Q-5 | 本次是否仅覆盖车机目标产品，还是要求所有端统一切到 `subProfileId` 维度实现？ | 这决定范围边界与兼容性要求 | 已澄清 |

### 讨论记录

| 日期 | 参与人 | 讨论主题 | 结论 | 后续动作 |
|------|--------|----------|------|----------|
| 2026-06-11 | 用户、Codex | 需求录入 | 已记录原始背景、接口清单与目标；尚未形成基线 | 等待需求方补充 Q-1 ~ Q-5 |
| 2026-06-11 | 用户、Codex | 核心接口与兼容策略 | 1) InnerKit 保留 `userId` 参数并新增 `subProfileId` 入参，但 `userId` 仅允许传 `0`；2) JS API 采用同名新增 `subProfileId` 入参签名；3) 统一使用 `subProfileId` 术语；4) 旧 `userId` 数据先被各 `subProfileId` 继承读取，但会约束新写入流程 | 继续确认目标产品范围、发行版本和 owner |
| 2026-06-11 | 用户、Codex | 产品范围与 feature 策略 | 仅车机生效；新增 feature 隔离；其他平台不定义该 feature 时，旧接口默认走原行为，同名新增 `subProfileId` 签名返回 `801` | 继续确认旧 JS API 兼容规则、发行版本和 owner |
| 2026-06-11 | 用户、Codex | 旧 JS API 兼容规则 | 旧 JS API 默认保持原行为；但一旦某 `userId` 已存在基于 `subProfileId` 的新数据，再调用不传 `subProfileId` 的旧接口执行设置时返回错误码 | 继续确认发行版本和 owner |
| 2026-06-11 | 用户、Codex | 版本与 Owner 占位 | 目标版本为 `master`；Owner 暂记 `TBD` | 等待需求方对 Define 基线做最终确认 |
| 2026-06-11 | 用户、Codex | `userId/subProfileId` 前置校验约束 | 1) InnerKit 新路径传入 `userId=0` 时获取 `callingUid` 计算当前 `userId`；2) InnerKit 新路径传入 `userId!=0` 时直接返回 `201`；3) 传入 `subProfileId>=0` 时需校验当前 `userId` 下是否存在对应 `subProfileId`，不存在则返回新增错误码；4) `subProfileId` 默认值为 `-1`，任何 `<0` 的场景统一按旧路径存取处理 | 纳入 API 约束、AC 和错误码设计 |

### 功能范围确认

| 问题 | 回答 | 确认人 | 状态 |
|------|------|--------|------|
| 核心功能包含哪些？ | 两类开关能力由 `userId` 维度扩展到可选 `subProfileId` 维度；InnerKit 保留 `userId` 参数并新增 `subProfileId` 入参，但 `userId` 仅支持传 `0`，JS 新增 `subProfileId` 维度签名；仅车机产品定义 feature 后启用 | 需求方 | 已确认 |
| 明确不包含哪些？ | Token sync、权限校验主流程、权限定义不在范围内；非车机平台不启用新 feature，保持原行为 | 需求方 | 已确认 |
| 是否有分期策略？ | 首期仅车机产品启用，其他平台不定义 feature | 需求方 | 已确认 |

### 方案探索

| 编号 | 方案概述 | 优势 | 风险/代价 | 选择结论 |
|------|----------|------|-----------|----------|
| A-1 | InnerKit 保留现有 `userId` 参数并新增 `subProfileId` 入参，且 `userId` 仅支持传 `0`；JS API 保持同名并新增 `subProfileId` 入参签名 | 兼容性更稳，参数位次延续现状；JS 层保留旧签名同时扩展新能力 | 需要处理默认值 `-1`、`callingUid` 解析、旧 `userId` 数据兼容阻塞、缓存/数据库清理和旧 JS API 行为定义 | 推荐 |
| A-2 | 保留所有现有接口不变，仅在服务内部尝试从 `userId` 推导 `subProfileId` | 改动面较小 | 无法精确表达多 subProfile 独立开关，不满足需求 | 放弃 |

**取舍理由：** 已确认 InnerKit 允许调整现有参数语义，而 JS 侧通过新增 API 承载新维度，兼顾车机能力扩展与现有 JS 接口兼容。

### 子系统影响

| 问题 | 回答 | 确认人 | 状态 |
|------|------|--------|------|
| 涉及哪些子系统？ | `security/access_token` 下 ATM 与 PrivacyManager 链路；需要联动车机 feature 配置与 `subProfileId` 语义提供方 | 需求方 | 已确认 |
| 是否需要新增子系统或部件？ | 否，仅在现有子系统内增加车机 feature 隔离 | 需求方 | 已确认 |

### API 变更评估

| 问题 | 回答 | 确认人 | 状态 |
|------|------|--------|------|
| 是否需要新增/修改 Public API？ | 否 | 需求方 | 已确认 |
| 是否需要新增 System API？ | 是，JS/ETS 新增 `subProfileId` 维度接口 | 需求方 | 已确认 |
| 是否会废弃已有 API？ | 否，旧 JS API 保留并维持原行为 | 需求方 | 已确认 |
| 是否需要新增权限声明？ | 否 | 需求方 | 已确认 |

### 兼容性与非功能需求

| 类别 | 核心问题 | 结论 | 确认人 | 状态 |
|------|----------|------|--------|------|
| 兼容性 | 旧 `userId` 维度调用和存量数据如何兼容 | 旧 `userId` 存量数据先对该 `userId` 下各 `subProfileId` 继承读取；仅车机定义 feature 时启用新行为，其他平台维持原行为；非车机调用同名新增 `subProfileId` 签名时直接返回 `801`；旧 JS API 默认保持原行为，但若某 `userId` 已存在基于 `subProfileId` 的新数据，则调用不传 `subProfileId` 的旧接口执行设置也返回错误码，此行为属于旧接口兼容性变更；若某 `userId` 仍存在旧数据，则按 `subProfileId` 执行 `status=true` 或 `status=false` 时都返回错误码，必须通过旧路径完成老数据清理后，才能基于 `subProfileId` 再设置；InnerKit 新路径保留 `userId` 参数并新增 `subProfileId` 入参，但 `userId` 仅支持传 `0`，服务端通过 `callingUid` 计算当前 `userId`，`subProfileId` 默认值为 `-1`，任何 `<0` 均按旧路径存取处理 | 需求方 | 已确认 |
| 性能 | 开关查询/设置不能明显增加热路径成本 | feature 未开启平台保持原路径；车机新增 `subProfileId` 维度不应引入明显性能回退 | 需求方 | 已确认 |
| 安全 | 子档案间必须隔离开关状态，避免串读串写 | 启用 feature 后必须按 `subProfileId` 隔离读写，旧 API 不可误入新语义 | 需求方 | 已确认 |
| 可靠性 | 持久化与内存态需保持一致 | 旧数据清理必须通过旧 `userId` 路径完成，并同步删除数据库和缓存中的旧记录；只有确认清理完成后，后续按 `subProfileId` 的新写入才允许生效；新增路径在 `subProfileId>=0` 时必须先校验该 `userId` 下是否存在对应 `subProfileId`，不存在则返回新增错误码；`subProfileId<0` 时统一按旧路径存取处理，不进入 profile 校验分支 | 需求方 | 已确认 |

### 依赖与风险

| 依赖项 | 类型 | 说明 | 状态 |
|--------|------|------|------|
| 车机 `subProfileId` 语义定义 | 运行/业务 | 已确认本需求统一使用 `subProfileId`，且仅车机产品启用 | 已确认 |

| 风险 | 类型 | 影响 | 缓解措施 | 状态 |
|------|------|------|----------|------|
| feature 开关定义不清导致车机/非车机行为分叉错误 | 技术 | 高 | 在 design/spec 中明确 feature 名称、默认值和未定义时回退原行为 | 已识别 |
| 旧数据未清理就按 `subProfileId` 访问新接口导致新旧语义并存 | 技术 | 高 | 在 spec/design 中定义明确错误码、旧路径清理顺序以及 DB/缓存一致性校验 | 已识别 |
| `userId` / `subProfileId` 前置校验不一致导致调用方行为混乱 | 技术 | 高 | 在 spec/design 中明确 `userId=0` 的 `callingUid` 解析、`userId!=0` 返回 `201`、以及 `subProfileId` 不存在时的新增错误码 | 已识别 |
| 已有 `subProfileId` 新数据后继续调用旧接口写入导致双写冲突 | 技术 | 高 | 在 spec/design 中明确旧接口写入阻塞规则和对应错误码 | 已识别 |

### AC 完整性

- [x] 每个用户故事有验收标准
- [x] AC 全部使用 WHEN/THEN 格式
- [x] 覆盖正常流程、异常流程、边界条件
- [x] AC 可测试、可度量

### 澄清结论

- [x] 功能范围已完全明确
- [x] 子系统影响已识别
- [x] API 变更已评估
- [x] 兼容性和非功能需求已确认
- [x] 依赖和风险已识别且有缓解方案
- [x] AC 完整可测试
- [x] 标准及以上复杂度已完成方案探索（至少 2 个方案 + 取舍理由）

**结论:** 通过

---

## 三、需求基线

> 澄清完成后固化。manifest.md 是事实源，此处为审批结论。

### 基线信息

| 字段 | 内容 |
|------|------|
| 基线版本 | v0-draft |
| 基线日期 | 2026-06-11 |
| Owner | TBD |
| 确认人 | 当前会话需求方（待最终基线确认） |
| 复杂度 | 标准 |
| Profile | none |
| 目标发行版本 | master |
| 版本状态 | proposed |

### 问题陈述

当前两类权限相关开关仅按 `userId` 生效，无法满足车机一个 `userId` 下多个 `subProfileId` 的隔离诉求，导致不同子档案之间的权限弹框策略和权限使用记录策略无法独立管理。

### 目标和成功指标

| 目标 | 成功指标 | 验证方式 |
|------|----------|----------|
| 支持 `subProfileId` 维度开关隔离 | 车机同一 `userId` 下不同 `subProfileId` 的开关状态可独立读写 | 单元测试 + 服务侧回归测试 |
| 保持非车机场景兼容 | 非车机平台未定义 feature 时旧接口保持原行为不变；同名新增 `subProfileId` 签名返回 `801`；车机已切入 `subProfileId` 新数据后，旧接口新增错误码属于兼容性变更，需单独回归验证 | feature 关闭路径回归测试 |
| 保持存量数据兼容 | 车机启用 feature 后，旧 `userId` 存量开关数据可被该 `userId` 下各 `subProfileId` 继承读取；当存在旧数据时，按 `subProfileId` 执行 `true` 或 `false` 都返回错误码，只有旧路径完成老数据 DB/缓存清理后才允许新的 `subProfileId` 写入 | 迁移/继承场景测试 |
| 保持新增路径入参约束一致 | InnerKit 新路径保留 `userId` 参数但仅允许传 `0`；JS 新签名不暴露 `userId`；`subProfileId` 默认 `-1` 且 `<0` 按旧路径存取；`subProfileId` 不存在时返回新增错误码 | 参数校验场景测试 |

### 用户故事与 AC

| Story ID | 用户故事 | 优先级 |
|----------|----------|--------|
| US-1 | 作为车机系统开发者，我希望按 `subProfileId` 管理权限弹框开关，以便不同子档案独立控制弹框行为 | P0 |
| US-2 | 作为车机系统开发者，我希望按 `subProfileId` 管理权限使用记录开关，以便不同子档案独立控制记录策略 | P0 |

| AC编号 | 验收标准 | 类型 | 关联Story |
|--------|----------|------|-----------|
| AC-1 | WHEN 车机产品定义新 feature 且调用新增权限弹框开关 API 传入 `subProfileId` THEN 同一 `userId` 下不同 `subProfileId` 的权限弹框开关状态可独立设置和读取 | 正常 | US-1 |
| AC-2 | WHEN 车机产品定义新 feature 且调用新增权限使用记录开关 API 传入 `subProfileId` THEN 同一 `userId` 下不同 `subProfileId` 的权限使用记录开关状态可独立设置和读取 | 正常 | US-2 |
| AC-3 | WHEN 车机产品定义新 feature 且某 `userId` 仍存在旧 `userId` 维度存量开关数据 THEN 该 `userId` 下各 `subProfileId` 读取结果继承该旧数据，且按 `subProfileId` 执行 `status=true` 或 `status=false` 设置时都返回约定错误码 | 边界 | US-1,US-2 |
| AC-4 | WHEN 车机产品定义新 feature 且某 `userId` 的旧数据已通过旧 `userId` 路径完成数据库和缓存清理 THEN 系统允许后续按 `subProfileId` 执行新的设置和读取 | 边界 | US-1,US-2 |
| AC-5 | WHEN 调用新增路径时传入 `userId=0` THEN 系统使用 `callingUid` 解析当前 `userId` 再继续后续 `subProfileId` 逻辑 | 正常 | US-1,US-2 |
| AC-6 | WHEN 调用新增路径时传入 `userId!=0` THEN 系统直接返回 `201` 错误码 | 异常 | US-1,US-2 |
| AC-7 | WHEN 调用新增路径且传入 `subProfileId>=0` 但当前 `userId` 下不存在该 `subProfileId` THEN 系统返回新增错误码 | 异常 | US-1,US-2 |
| AC-8 | WHEN 某 `userId` 已存在基于 `subProfileId` 的新数据 AND 调用不传 `subProfileId` 的旧接口执行设置 THEN 系统返回约定错误码 | 兼容性 | US-1,US-2 |
| AC-9 | WHEN 非车机平台未定义该 feature 且调用同名新增 `subProfileId` 签名 THEN 系统返回 `801` 错误码 | 兼容性 | US-1,US-2 |
| AC-10 | WHEN 非车机平台未定义该 feature 或调用旧 JS API 且当前 `userId` 尚不存在任何 `subProfileId` 新数据 THEN 系统保持原有 `userId` / 旧行为，不引入 `subProfileId` 语义变化 | 兼容性 | US-1,US-2 |

### 范围边界

**包含：** 两类开关能力的 `subProfileId` 维度扩展；InnerKit 参数语义切换；JS 新增接口；旧 `userId` 数据兼容阻塞与清理策略；车机 feature 隔离。
**不包含：** token sync、普通权限校验流程、权限定义变更、非车机平台行为变更。

### 影响范围

| 子系统 | 仓库 | 模块/路径 | 当前职责 | 影响类型 | Owner |
|--------|------|-----------|----------|----------|-------|
| AccessTokenManager | security_access_token | `interfaces/innerkits/accesstoken` / `frameworks/js,napi/ets/accesstoken` / `services/accesstokenmanager` | 权限弹框开关对外接口与服务实现 | 修改/API | 待确认 |
| PrivacyManager | security_access_token | `interfaces/innerkits/privacy` / `frameworks/js,napi/ets/privacy` / `services/privacymanager` | 权限使用记录开关对外接口与服务实现 | 修改/API | 待确认 |

### API 变更项清单

| API 名称 | 变更类型 | 开放范围 | 概要说明 |
|----------|----------|----------|----------|
| `AccessTokenKit::Set/GetPermissionRequestToggleStatus` | 修改 | InnerAPI | 保留 `userId` 参数并新增 `subProfileId` 入参；`userId` 仅允许传 `0`，`subProfileId` 默认值为 `-1`，`<0` 按旧路径存取处理 |
| `PrivacyKit::Set/GetPermissionUsedRecordToggleStatus` | 修改 | InnerAPI | 保留 `userId` 参数并新增 `subProfileId` 入参；`userId` 仅允许传 `0`，`subProfileId` 默认值为 `-1`，`<0` 按旧路径存取处理 |
| `set/getPermissionRequestToggleStatus` | 新增 | JS/System API | 同名新增 `subProfileId` 入参签名；仅车机可用，非车机调用返回 `801`；旧签名保留并维持原行为 |
| `set/getPermissionUsedRecordToggleStatus` | 新增 | JS/System API | 同名新增 `subProfileId` 入参签名；仅车机可用，非车机调用返回 `801`；旧签名保留并维持原行为 |

### 不涉及项确认

| 维度 | 涉及？ | 依据 | 若涉及，进入哪个下游文档 |
|------|--------|------|--------------------------|
| 性能 | 是 | 查询维度变化可能影响热路径 | design.md / spec.md |
| 安全与权限 | 是 | 子档案隔离属于权限/隐私边界 | design.md / spec.md |
| 兼容性 | 是 | 旧接口与旧数据兼容策略已确认，仍需在 spec 固化细则 | spec.md |
| API/SDK | 是 | InnerKit/JS API 行为可能变更 | design.md / spec.md |
| IPC/跨进程 | 是 | ATM/Privacy 服务 IPC 入参可能调整 | design.md |
| 构建与部件 | 是 | 需增加车机专属 feature 隔离与默认回退行为 | design.md |
| 国际化/无障碍 | 否 | 无 UI 文案变更 | N/A |
| 数据迁移 | 是 | 旧 `userId` 存量开关数据需支持继承读取、旧路径触发的 DB/缓存清理、清理后的 `subProfileId` 新写入，以及已有 `subProfileId` 新数据时对旧接口写入的阻塞 | design.md / spec.md |
| 错误码 | 是 | 需明确复用 `201` 的场景，以及 `subProfileId` 不存在时的新增错误码 | design.md / spec.md |

### 基线结论

当前需求边界、兼容策略、非功能要求、目标版本和 Owner 占位信息均已补齐，且需求方已于 2026-06-11 明确批准进入 Stage 2。

**结论：** 通过

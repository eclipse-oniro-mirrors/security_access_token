# 特性规格

## 概述

| 属性 | 值 |
|------|-----|
| 特性名称 | 车机 `subProfileId` 维度权限开关 |
| 特性编号 | FEAT-permission-toggle-management-based-subprofileid |
| 所属 Epic | 无 |
| 优先级 | P0 |
| 目标版本 | `master` |
| SIG 归属 | security |
| 状态 | Draft |
| 复杂度 | 标准 |

## 本次变更范围（Delta）

| 类型 | 内容 | 说明 |
|------|------|------|
| ADDED | JS/ETS 原函数名新增带 `subProfileId` 入参的新签名 | 仅 `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 定义时可用；未定义时调用新增签名返回 `801` |
| MODIFIED | InnerKit 开关接口签名 | 保留原 `userId` 参数位，新增 `subProfileId` 入参，默认值为 `-1`；`userId` 仅允许传 `0`；`subProfileId<0` 按旧路径存取；未定义 feature 时服务端统一按 `-1` 处理 |
| MODIFIED | 开关兼容规则 | 老数据存在时，新路径写入一律报错；新数据存在时，旧接口写入也报错，且该错误返回属于旧接口兼容性变更 |
| MODIFIED | 新路径参数约束 | JS 新接口不暴露 `userId`，服务端使用 `callingUid`；非 JS 新路径若传 `userId!=0` 返回 `201` |
| REMOVED | 无 | 旧 API 不删除 |

## 输入文档

| 文档 | 路径 | 状态 |
|------|------|------|
| Requirement | `[proposal.md]` | Approved |

## 用户故事

### US-1: 车机 `subProfileId` 权限弹框开关

**作为** 车机系统开发者，  
**我想要** 按 `subProfileId` 设置和查询权限弹框开关，  
**以便** 不同子档案独立控制权限弹框行为。

**验收标准：**

- **AC-1.1:** WHEN 车机产品定义新 feature 且调用新增权限弹框开关 API 传入合法 `subProfileId` THEN 系统应当按当前 `userId + subProfileId + permissionName` 维度独立设置和读取开关
- **AC-1.2:** WHEN 调用新增权限弹框开关 JS 接口 THEN 系统应当从 `callingUid` 解析当前 `userId`
- **AC-1.3:** WHEN 新路径传入的 `subProfileId>=0` 且 `callingUid` 解析出的当前 `userId` 下不存在对应 `subProfileId` THEN 系统应当返回新增错误码
- **AC-1.4:** WHEN 该 `userId` 仍存在旧 `userId` 维度存量弹框开关数据 THEN 新路径对该 `subProfileId` 执行 `status=true` 或 `status=false` 都应返回兼容错误码
- **AC-1.5:** WHEN InnerKit 新路径传入 `subProfileId<0` THEN 系统应当按旧路径执行弹框开关存取

### US-2: 车机 `subProfileId` 权限使用记录开关

**作为** 车机系统开发者，  
**我想要** 按 `subProfileId` 设置和查询权限使用记录开关，  
**以便** 不同子档案独立控制记录策略。

**验收标准：**

- **AC-2.1:** WHEN 车机产品定义新 feature 且调用新增权限使用记录开关 API 传入合法 `subProfileId` THEN 系统应当按当前 `userId + subProfileId` 维度独立设置和读取开关
- **AC-2.2:** WHEN 调用新增权限使用记录开关 JS 接口 THEN 系统应当从 `callingUid` 解析当前 `userId`
- **AC-2.3:** WHEN 新路径传入的 `subProfileId>=0` 且 `callingUid` 解析出的当前 `userId` 下不存在对应 `subProfileId` THEN 系统应当返回新增错误码
- **AC-2.4:** WHEN 该 `userId` 仍存在旧 `userId` 维度存量记录开关数据 THEN 新路径对该 `subProfileId` 执行 `status=true` 或 `status=false` 都应返回兼容错误码
- **AC-2.5:** WHEN InnerKit 新路径传入 `subProfileId<0` THEN 系统应当按旧路径执行使用记录开关存取

### US-3: 兼容与回退

**作为** 系统维护者，  
**我想要** 在老数据和 feature 未定义场景下保持行为可控，
**以便** 避免引入回归和新旧语义并存。

**验收标准：**

- **AC-3.1:** WHEN 车机产品定义新 feature 且某 `userId` 仍存在旧 `userId` 维度存量开关数据 THEN 该 `userId` 下各 `subProfileId` 的读取结果应继承该旧数据
- **AC-3.2:** WHEN 该 `userId` 的旧数据已通过旧路径完成数据库和缓存清理 THEN 系统应当允许后续按 `subProfileId` 执行新的设置和读取
- **AC-3.3:** WHEN 某 `userId` 已存在基于 `subProfileId` 的新数据 AND 调用不传 `subProfileId` 的旧接口执行设置 THEN 系统应当返回兼容错误码
- **AC-3.4:** WHEN `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 未定义且调用同名新增 `subProfileId` 签名 THEN 系统应当返回 `801`
- **AC-3.5:** WHEN `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 未定义或调用旧 JS API 且当前 `userId` 尚不存在任何 `subProfileId` 新数据 THEN 系统应当保持原有 `userId` / 旧行为，不引入 `subProfileId` 语义变化

## 验收追溯

| AC | 关联规则 | 关联 Task | 验证方式 | 证据 |
|----|----------|-----------|----------|------|
| AC-1.1 | BR-1, FR-1 | TASK-1,TASK-2,TASK-3 | 单测/集成 | `tests/test-design.md` TC-01/TC-33；`tests/test-cases.md` CASE-ATM-KIT-001/CASE-VEHICLE-ATM-031；`hb build access_token -t --gn-args use_cfi=false use_thin_lto=false` |
| AC-1.2 | BR-2 | TASK-1,TASK-2,TASK-3 | 单测/服务 | `tests/test-design.md` TC-03；`tests/test-cases.md` CASE-ATM-SVC-010；`SetToggleStatusWithResolvedUserId001` / `GetToggleStatusWithResolvedUserId001` |
| AC-1.3 | BR-3, EX-2, FR-8 | TASK-1,TASK-2,TASK-3 | 单测 | `tests/test-design.md` TC-05/TC-29；`tests/test-cases.md` CASE-ATM-SVC-011/CASE-ATM-SVC-014；service not-exist 分支用例 |
| AC-1.4 | BR-4, EX-3 | TASK-2,TASK-3 | 单测/集成 | `tests/test-design.md` TC-07/TC-08；`tests/test-cases.md` CASE-ATM-KIT-002；ATM storage conflict 用例 |
| AC-1.5 | BR-6, FR-6 | TASK-2,TASK-3 | 单测 | `tests/test-design.md` TC-11；`tests/test-cases.md` CASE-ATM-KIT-003；ATM negative `subProfileId` 用例 |
| AC-2.1 | BR-1, FR-2 | TASK-1,TASK-2,TASK-4 | 单测/集成 | `tests/test-design.md` TC-02/TC-34；`tests/test-cases.md` CASE-PRI-KIT-015/CASE-VEHICLE-PRI-032；`hb build access_token -t --gn-args use_cfi=false use_thin_lto=false` |
| AC-2.2 | BR-2 | TASK-1,TASK-2,TASK-4 | 单测/服务 | `tests/test-design.md` TC-04；`tests/test-cases.md` CASE-PRI-SVC-023；`SetToggleStatusWithResolvedUserId001` / `GetToggleStatusWithResolvedUserId001` |
| AC-2.3 | BR-3, EX-2, FR-8 | TASK-1,TASK-2,TASK-4 | 单测 | `tests/test-design.md` TC-06/TC-30；`tests/test-cases.md` CASE-PRI-SVC-024/CASE-PRI-SVC-027；service not-exist 分支用例 |
| AC-2.4 | BR-4, EX-3 | TASK-2,TASK-4 | 单测/集成 | `tests/test-design.md` TC-09/TC-10；`tests/test-cases.md` CASE-PRI-KIT-016；Privacy storage conflict 用例 |
| AC-2.5 | BR-6, FR-6 | TASK-2,TASK-4 | 单测 | `tests/test-design.md` TC-12；`tests/test-cases.md` CASE-PRI-KIT-017；Privacy negative `subProfileId` 用例 |
| AC-3.1 | BR-4, BR-7, BR-8, FR-3, FR-7, FR-9 | TASK-2,TASK-3,TASK-4 | 单测/集成/手工 | `tests/test-design.md` TC-13/TC-14/TC-25/TC-26/TC-37/TC-38；`tests/test-cases.md` 对应用例 |
| AC-3.2 | BR-7, BR-8, FR-4, FR-9, RC-1 | TASK-2,TASK-3,TASK-4 | 单测/集成/手工 | `tests/test-design.md` TC-15/TC-16/TC-37/TC-38；`tests/test-cases.md` CASE-ATM-KIT-005/CASE-PRI-KIT-019/OTA 用例 |
| AC-3.3 | BR-5, FR-5, EX-4 | TASK-2,TASK-3,TASK-4 | 单测/集成 | `tests/test-design.md` TC-17/TC-18；`tests/test-cases.md` CASE-ATM-KIT-006/CASE-PRI-KIT-020 |
| AC-3.4 | BR-1, BR-9, EX-0 | TASK-1,TASK-2,TASK-5 | 宏分支单测/回归 | `tests/test-design.md` TC-19/TC-20/TC-31/TC-32；`tests/test-cases.md` CASE-ATM-KIT-007/CASE-PRI-KIT-021/CASE-FEATURE-OFF-029；feature off `#else` 用例 |
| AC-3.5 | BR-1, BR-9 | TASK-1,TASK-2,TASK-5 | 宏分支单测/回归 | `tests/test-design.md` TC-21/TC-22/TC-28；`tests/test-cases.md` CASE-ATM-KIT-008/CASE-PRI-KIT-022/CASE-ATM-KIT-009；feature off `#else` 用例 |

## 业务规则

| 编号 | 规则描述 | 约束条件 | 关联 AC |
|------|----------|----------|---------|
| BR-1 | 新路径仅在 `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 开启时使用 `subProfileId` 语义 | feature 未定义时，同名新增 `subProfileId` 签名返回 `801` | AC-1.1, AC-2.1, AC-3.5 |
| BR-2 | JS 新路径不暴露 `userId`，服务端统一通过 `callingUid` 解析 | 非 JS 新路径若传 `userId!=0` 直接返回 `201` | AC-1.2, AC-2.2 |
| BR-3 | 新路径中的 `subProfileId` 必须属于 `callingUid` 解析出的当前 `userId` | 不存在返回新增错误码 | AC-1.3, AC-2.3 |
| BR-4 | 老 `userId` 数据存在时，新路径只允许继承读取，不允许写入 | `status=true/false` 都返回兼容错误码 | AC-1.4, AC-2.4, AC-3.1 |
| BR-5 | 已存在 `subProfileId` 新数据时，旧接口不允许再执行设置 | 调用不传 `subProfileId` 的旧接口设置时返回兼容错误码 | AC-3.3 |
| BR-6 | `subProfileId<0` 按旧路径处理 | 不进入 `subProfileId` 维度校验和新路径存储 | AC-1.5, AC-2.5 |
| BR-9 | 未定义 feature 时服务端统一将任意 InnerKit `subProfileId` 归一化为 `-1` | 仅 feature 开启场景保留 `subProfileId>=0` 语义；JS/ETS 新签名在 feature 未定义时返回 `801` | AC-3.4, AC-3.5 |
| BR-7 | 数据库通过 `sub_profile_id` 列区分旧路径与新路径数据 | `sub_profile_id = -1` 表示旧路径，`sub_profile_id >= 0` 表示新路径 | AC-3.1, AC-3.2, AC-3.3 |
| BR-8 | 数据库升级新增 `sub_profile_id` 列时历史记录按旧路径处理 | 升级后历史数据统一视为 `sub_profile_id = -1` | AC-3.1, AC-3.2 |

## 功能规则

| 编号 | 规则描述 | 触发条件 | 作用对象 | 关联 AC |
|------|----------|----------|----------|---------|
| FR-1 | 权限弹框开关新路径按 `userId + subProfileId + permissionName` 维度隔离 | feature 开启且校验通过 | ATM 开关记录 | AC-1.1 |
| FR-2 | 权限使用记录开关新路径按 `userId + subProfileId` 维度隔离 | feature 开启且校验通过 | Privacy 开关记录 | AC-2.1 |
| FR-3 | 老数据读取继承旧 `userId` 结果 | 老数据存在且新路径查询 | ATM/Privacy 查询 | AC-3.1 |
| FR-4 | 旧路径清理完成后允许切换到新路径写入 | 老数据已清理 | ATM/Privacy 设置 | AC-3.2 |
| FR-5 | 新路径写入成功后，旧接口进入写入阻塞状态 | 已存在 `subProfileId` 新数据 | ATM/Privacy 旧接口设置 | AC-3.3 |
| FR-6 | 当 `subProfileId<0` 时直接复用旧路径读写 | `subProfileId<0` | ATM/Privacy 旧路径存取 | AC-1.5, AC-2.5 |
| FR-7 | 新路径查询在仅存在旧记录时继承旧记录值 | `sub_profile_id = -1` 旧记录存在且无新记录 | ATM/Privacy 查询 | AC-3.1 |
| FR-8 | `subProfileId >= 0` 时必须校验其属于当前 `userId` | feature 开启且 `subProfileId >= 0` | ATM/Privacy 新路径入口 | AC-1.3, AC-2.3 |
| FR-9 | 数据库升级后历史记录默认走旧路径语义 | 历史记录 `sub_profile_id` 缺省或初始化为 `-1` | ATM/Privacy 读写 | AC-3.1, AC-3.2 |

## 异常/豁免规则

| 编号 | 异常码/枚举 | 规则描述 | 触发条件 | 超时阈值 | 处理结果 | 关联 AC |
|------|------------|----------|----------|----------|----------|---------|
| EX-0 | `801` | feature 未定义时不支持新签名 | `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 未定义时调用同名新增 `subProfileId` 签名 | N/A | 直接返回错误码 | AC-3.4 |
| EX-1 | `201` | 非法内部 `userId` | 非 JS 新路径传入 `userId!=0` | N/A | 直接返回错误码 | 内部路径约束 |
| EX-2 | `ERR_PERMISSION_REQUEST_TOGGLE_SUBPROFILE_NOT_EXIST` / `ERR_PERMISSION_USED_RECORD_SUBPROFILE_NOT_EXIST` | `subProfileId` 不存在 | `subProfileId>=0` 且不属于 `callingUid` 解析出的当前 `userId` | N/A | ATM/Privacy 分别返回对应的 subProfile 不存在错误码 | AC-1.3, AC-2.3 |
| EX-3 | `ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT` / `ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT` | 存储模式冲突阻塞新路径写入 | 旧 `userId` 数据存在且新路径 set `true/false` | N/A | ATM/Privacy 分别返回对应冲突错误码 | AC-1.4, AC-2.4 |
| EX-4 | `ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT` / `ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT` | 存储模式冲突阻塞旧接口写入 | 已存在 `subProfileId` 新数据且旧接口执行设置 | N/A | ATM/Privacy 分别返回对应冲突错误码 | AC-3.3 |

## 恢复契约

| 编号 | 触发条件 | 恢复策略 | 恢复结果 | 约束 |
|------|----------|----------|----------|------|
| RC-1 | 同一 `userId` 的旧数据已通过旧路径清理完成 | 允许新路径重新尝试 `subProfileId` 设置/读取 | 新路径按 `subProfileId` 语义正常工作 | 清理必须同时覆盖数据库和缓存 |

## 验证映射

| 编号 | 对应规格项 | 验证方式 | 验证重点 |
|------|------------|----------|----------|
| VM-1 | BR-2 | 单测 | JS 新接口 `callingUid` 解析分支 |
| VM-2 | BR-3 / EX-2 | 单测 | `subProfileId` 存在性校验和对应子系统的 subProfile 不存在错误码 |
| VM-3 | BR-4 / EX-3 | 单测/集成 | 老数据阻塞 `true/false` 写入 |
| VM-4 | BR-5 / EX-4 | 单测/集成 | 新数据存在时旧接口写入被阻塞 |
| VM-5 | BR-6 / FR-6 | 单测 | `subProfileId<0` 按旧路径存取 |
| VM-6 | RC-1 | 集成 | 旧路径清理后切换成功 |
| VM-7 | BR-1 / EX-0 | 回归 | feature 未定义时调用新签名返回 `801` |
| VM-8 | BR-1 / AC-3.5 | 回归 | feature 未定义时旧 API 保持原行为 |

## API 变更分析

### 新增 API

| API 名称 | 开放范围 | 入参概要 | 返回值 | 错误码范围 | 功能描述 | 关联 AC |
|----------|----------|----------|--------|------------|----------|---------|
| `setPermissionRequestToggleStatus`（新增带 `subProfileId` 入参签名） | System | `subProfileId`, `permissionName`, `status` | Promise<void> / retCode | 成功码、`801`、`ERR_PERMISSION_REQUEST_TOGGLE_SUBPROFILE_NOT_EXIST`、`ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT` | 按 `subProfileId` 设置弹框开关 | AC-1.1~AC-1.4, AC-3.4 |
| `getPermissionRequestToggleStatus`（新增带 `subProfileId` 入参签名） | System | `subProfileId`, `permissionName` | Promise<status> / retCode | 成功码、`801`、`ERR_PERMISSION_REQUEST_TOGGLE_SUBPROFILE_NOT_EXIST` | 按 `subProfileId` 查询弹框开关 | AC-1.1~AC-1.3, AC-3.4 |
| `setPermissionUsedRecordToggleStatus`（新增带 `subProfileId` 入参签名） | System | `subProfileId`, `status` | Promise<void> / retCode | 成功码、`801`、`ERR_PERMISSION_USED_RECORD_SUBPROFILE_NOT_EXIST`、`ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT` | 按 `subProfileId` 设置使用记录开关 | AC-2.1~AC-2.4, AC-3.4 |
| `getPermissionUsedRecordToggleStatus`（新增带 `subProfileId` 入参签名） | System | `subProfileId` | Promise<boolean> / retCode | 成功码、`801`、`ERR_PERMISSION_USED_RECORD_SUBPROFILE_NOT_EXIST` | 按 `subProfileId` 查询使用记录开关 | AC-2.1~AC-2.3, AC-3.4 |

### 变更/废弃 API

| API 名称 | 变更类型 | 影响场景 | 迁移指引 | 关联 AC |
|----------|----------|----------|----------|---------|
| `AccessTokenKit::Set/GetPermissionRequestToggleStatus` | 变更 | InnerKit 调用方新增可选 `subProfileId` 入参，且 `userId` 仅允许传 `0` | 旧调用方若使用新路径需改为传 `userId=0`；`subProfileId<0` 时按旧路径处理；新调用方可显式传 `subProfileId>=0` | AC-1.1, AC-1.5 |
| `PrivacyKit::Set/GetPermissionUsedRecordToggleStatus` | 变更 | InnerKit 调用方新增可选 `subProfileId` 入参，且 `userId` 仅允许传 `0` | 旧调用方若使用新路径需改为传 `userId=0`；`subProfileId<0` 时按旧路径处理；新调用方可显式传 `subProfileId>=0` | AC-2.1, AC-2.5 |
| `AccessTokenKit::GetTokenIDByUserID` | 变更 | SDK kit 新增可选 `subProfileId` 入参；client/service/IDL 显式透传 | 仅 `AccessTokenKit` 保留默认值 `-1`；未定义 feature 时服务端统一按 `-1` 处理 | AC-1.1, AC-3.5 |
| 旧 JS API | 兼容性变更 | 现有系统调用方 | 无需迁移；但若已存在 `subProfileId` 新数据，旧接口设置返回对应子系统的 storage mode conflict 错误码 | AC-3.3, AC-3.5 |

## 兼容性声明

- **已有 API 行为变更:** 是，InnerKit 新增可选 `subProfileId` 入参且 `userId` 仅允许传 `0`，其中 `subProfileId<0` 按旧路径处理；旧 JS API 在“已存在 `subProfileId` 新数据”场景下新增写入错误返回，属于兼容性变更
- **配置文件格式变更:** 否
- **数据存储格式变更:** 是，新路径引入 `subProfileId` 维度
- **数据库兼容方式:** 同表新增 `sub_profile_id` 列，`-1` 表示旧路径，`>=0` 表示新路径；不做自动迁移
- **最低支持版本:** `master`
- **API 版本号策略:** 新增 System API 按新版本标注；旧 API 保持原版本

## 架构约束

| 关键约束 | 约束说明 | 影响 AC |
|----------|----------|---------|
| 仅车机 feature 开启时生效 | 未开启 feature 时，同名新增 `subProfileId` 签名返回 `801` | AC-1.1, AC-2.1, AC-3.4 |
| JS 新路径不暴露 `userId` | 系统通过 `callingUid` 解析当前 `userId` | AC-1.2, AC-2.2 |
| `subProfileId` 必须属于当前 `userId` | 不存在返回新增错误码 | AC-1.3, AC-2.3 |
| 老数据阻塞新路径写入 | `status=true/false` 都报错 | AC-1.4, AC-2.4, AC-3.1 |
| 新数据阻塞旧接口写入 | 不传 `subProfileId` 的旧接口设置报错 | AC-3.3 |
| `subProfileId<0` 按旧路径存取 | 不进入 `subProfileId` 维度新逻辑 | AC-1.5, AC-2.5 |

## 非功能性需求

| 类型 | 指标/阈值 | 验证方式 | 证据 |
|------|-----------|----------|------|
| 性能 | feature 关闭时无可感知行为回退 | 宏分支回归测试 | `tests/test-design.md` TC-21/TC-22/TC-28；feature off `#else` 用例 |
| 安全 | 新路径必须校验 `subProfileId` 归属，禁止跨 profile 读写 | 单测/审查 | `tests/test-design.md` TC-29/TC-30；`tests/test-cases.md` CASE-ATM-SVC-014/CASE-PRI-SVC-027 |
| 可靠性 | 旧路径清理完成前，新路径持续稳定返回兼容错误码；新数据存在时旧接口稳定返回兼容错误码 | 单测/集成 | `tests/test-design.md` TC-07~TC-18；`tests/test-cases.md` 冲突与切换用例 |
| 问题定位 | `801`、`JS_ERROR_STORAGE_MODE_CONFLICT`、`JS_ERROR_SUBPROFILE_NOT_EXIST` 以及对应 native 错误码可区分问题原因；内部非法 `userId` 路径仍可定位 `201` | 单测/hilog | `tests/test-design.md` TC-36；`tests/test-cases.md` CASE-ERROR-033 |

## 多设备适配声明

| 设备类型 | 行为差异 | 规格/约束 | 验证方式 | 证据 |
|----------|----------|-----------|----------|------|
| 未定义 `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 的产品 | 新签名不可用 | 调用同名新增 `subProfileId` 签名返回 `801`；旧路径保持原行为 | 宏分支回归测试 | `tests/test-design.md` TC-19~TC-22/TC-28/TC-31/TC-32；feature off `#else` 用例 |
| 定义 `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 的产品 | 启用 `subProfileId` 新路径 | 受老数据阻塞和参数校验约束 | 单测/集成 | `tests/test-design.md` TC-33/TC-34；`tests/test-cases.md` CASE-VEHICLE-ATM-031/CASE-VEHICLE-PRI-032 |

## 全局特性影响

| 特性 | 适用？ | 结论 | 关联场景 |
|------|--------|------|----------|
| 无障碍 | N/A | 无 UI 变化 | N/A |
| 大字体 | N/A | 无 UI 变化 | N/A |
| 深色模式 | N/A | 无 UI 变化 | N/A |
| 多窗口/分屏 | N/A | 无 UI 变化 | N/A |
| 多用户 | 是 | `userId` 仍是上层用户维度，`subProfileId` 是车机子档案维度 | AC-1.1, AC-2.1 |
| 版本升级 | 是 | 老数据不自动迁移，需沿旧路径清理 | AC-3.1, AC-3.2 |
| 生态兼容 | 是 | feature 未定义时旧 API 保持原行为；新增 `subProfileId` 签名返回 `801` | AC-3.4, AC-3.5 |

## 行为场景（可选，Gherkin）

```gherkin
Feature: Vehicle subProfileId toggle status
  作为 车机系统开发者
  我想要 按 subProfileId 管理权限相关开关
  以便 不同子档案独立控制权限行为

  Scenario: JS 新接口通过 callingUid 取当前 userId
    Given 车机产品开启新 feature
    When 调用新增 API 且以第一个入参传入 subProfileId
    Then 系统使用 callingUid 解析当前 userId

  Scenario: 老数据阻塞新写入
    Given 当前 userId 仍存在旧 userId 维度存量开关数据
    When 调用新增 API 对任一 subProfileId 执行 status=true 或 status=false
    Then 系统返回兼容错误码

  Scenario: 新数据阻塞旧接口写入
    Given 当前 userId 已存在基于 subProfileId 的新数据
    When 调用不传 subProfileId 的旧接口执行设置
    Then 系统返回兼容错误码

  Scenario: subProfileId 不存在
    Given 车机产品开启新 feature
    When 调用新增 API 且 subProfileId 不属于当前 userId
    Then 系统返回新增错误码

  Scenario: feature 未定义时调用新签名
    Given 产品未定义 ACCESS_TOKEN_SUPPORT_SUBPROFILE
    When 调用同名新增 subProfileId 签名
    Then 系统返回 801
```

## Spec 自审清单

- [x] 无"待定""TBD""TODO"等占位符
- [x] 所有 AC 使用 WHEN/THEN 格式，可独立测试
- [x] 范围边界明确（做什么/不做什么清晰）
- [x] 无语义模糊表述（"快速""稳定""尽可能"等）
- [x] AC 与业务规则/异常规则/恢复契约交叉一致

## context-references

```yaml
context-queries:
  - repo: "openharmony/security_access_token"
    query: "permission request toggle and permission used record toggle current service/storage chain"
```

**关键文档：** `proposal.md`, 当前仓 `AGENTS.md`

# 任务规格

## 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-1 |
| 标题 | NAPI/ANI 同名新签名与错误码透传 |
| 关联 Feature | FEAT-permission-toggle-management-based-subprofileid |
| 目标仓库 | security_access_token |
| 目标模块 | `frameworks/js/napi/*`, `frameworks/ets/ani/*` |
| 分支 | 当前工作分支 |
| 优先级 | P0 |
| 复杂度 | 中 |
| 执行方式 | 主线程顺序执行 |

## 任务描述

### 做什么

1. 为 JS/ETS 原函数新增 `subProfileId` 位于最后一个入参的新签名。
2. 在 NAPI/ANI 层把 `801`、ATM/Privacy `SUBPROFILE_NOT_EXIST`、`STORAGE_MODE_CONFLICT` 错误码正确透传到 JS/ETS。

### 不做什么

- 不修改数据库结构。
- 不实现 ATM/Privacy 存储冲突规则本体。

## 规格映射与边界

### AC 映射

| AC | 来源 | 验证方式 |
|----|------|----------|
| AC-1.1 | spec.md | 单测/编译 |
| AC-1.2 | spec.md | 单测 |
| AC-2.1 | spec.md | 单测/编译 |
| AC-2.2 | spec.md | 单测 |
| AC-3.4 | spec.md | 回归 |
| AC-3.5 | spec.md | 回归 |

### 前置依赖

| 类型 | 编号 | 原因 |
|------|------|------|
| Context | design.md/spec.md | API 契约来源 |

### 完成判据

- JS/ETS/NAPI/ANI 新签名与旧签名并存且可编译。
- 新签名的错误码透传路径完整。

### 停止条件

- 同名重载在 ETS/ANI 绑定层无法表达。

## 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `frameworks/js/napi/accesstoken/*` | abilityAccessCtrl NAPI |
| 修改 | `frameworks/js/napi/privacy/*` | privacyManager NAPI |
| 修改 | `frameworks/ets/ani/accesstoken/*` | abilityAccessCtrl ANI/ETS |
| 修改 | `frameworks/ets/ani/privacy/*` | privacyManager ANI/ETS |

## 验证检查清单

- [√] 新签名编译通过
- [x] 错误码可透传
- [x] 未修改任务范围外文件

## 本次实现文件范围

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `interfaces/kits/js/napi/accesstoken/include/napi_atmanager.h` | ATM NAPI 结构与声明扩展 |
| 修改 | `frameworks/js/napi/accesstoken/src/napi_atmanager.cpp` | ATM NAPI 参数解析与新签名 |
| 修改 | `frameworks/ets/ani/accesstoken/src/ani_ability_access_ctrl.cpp` | ATM ANI native execute 扩展 |
| 修改 | `frameworks/ets/ani/accesstoken/ets/@ohos.abilityAccessCtrl.ets` | ATM ETS 同名新签名 |
| 修改 | `interfaces/kits/js/napi/privacy/include/permission_record_manager_napi.h` | Privacy NAPI 结构与声明扩展 |
| 修改 | `frameworks/js/napi/privacy/src/permission_record_manager_napi.cpp` | Privacy NAPI 参数解析与新签名 |
| 修改 | `frameworks/ets/ani/privacy/src/privacy_manager.cpp` | Privacy ANI native execute 扩展 |
| 修改 | `frameworks/ets/ani/privacy/ets/@ohos.privacyManager.ets` | Privacy ETS 同名新签名 |

## 完成证据

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 构建 | `hb build access_token -i --fast-rebuild` | PASS |

## 自检结论

| 项 | 结果 | 说明 |
|----|------|------|
| 同名新签名接线 | PASS | JS/NAPI/ANI/ETS 已接通 |
| `subProfileId` 首参 | PASS | 新签名顺序已对齐 |
| NAPI/ANI 错误码转换 | PASS | JS/ANI 专用错误码已映射 |
| 导出符号更新 | PASS | SDK map 已同步 |
| 单测/回归测试证据 | PENDING | 归属 `TASK-5` |

说明：`TASK-1` 可视为实现层完成并具备编译通过证据，但整体验证仍待 `TASK-5` 补齐测试证据。

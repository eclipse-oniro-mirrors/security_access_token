# 任务规格

## 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-5 |
| 标题 | 单测与回归测试补齐 |
| 关联 Feature | FEAT-permission-toggle-management-based-subprofileid |
| 目标仓库 | security_access_token |
| 目标模块 | `interfaces/innerkits/*/test/*`, `services/*/test/*` |
| 分支 | 当前工作分支 |
| 优先级 | P0 |
| 复杂度 | 中 |
| 执行方式 | 主线程顺序执行 |

## 任务描述

### 做什么

1. 为 JS/NAPI/ANI、InnerKit、服务、数据库兼容补齐单测。
2. 增加车机/非车机关键回归场景，包括 `801`、`201`、`subProfileId<0` 旧路径、双向冲突。
3. 维护测试设计与测试用例产物，确保每个测试点有明确测试规格和建议落点。

### 不做什么

- 不新增与本需求无关的测试基础设施。

## 规格映射与边界

### AC 映射

| AC | 来源 | 验证方式 |
|----|------|----------|
| AC-3.2 | spec.md | 集成 |
| AC-3.4 | spec.md | 回归 |
| AC-3.5 | spec.md | 回归 |

### 前置依赖

| 类型 | 编号 | 原因 |
|------|------|------|
| Task | TASK-3 | ATM 规则已落地 |
| Task | TASK-4 | Privacy 规则已落地 |

### 完成判据

- 关键规则有 fresh verification evidence。
- 回归覆盖旧路径、新路径、非车机禁用、升级兼容。
- [tests/test-cases.md](../tests/test-cases.md) 中每个 P0 测试点均已映射到明确的测试文件或实现计划。

### 停止条件

- 关键测试依赖当前仓外部产品配置且无法在本仓复现。

## 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `.spec/features/permission-toggle-management-based-subprofileid/tests/test-design.md` | 维护测试设计总表与分层策略 |
| 新增 | `.spec/features/permission-toggle-management-based-subprofileid/tests/test-cases.md` | 维护逐条测试用例规格 |
| 修改 | `interfaces/innerkits/*/test/*` | InnerKit 与参数规则测试 |
| 修改 | `services/accesstokenmanager/test/unittest/*` | ATM 测试 |
| 修改 | `services/privacymanager/test/unittest/*` | Privacy 测试 |

## 验证检查清单

- [ ] `801` 回归
- [ ] `201` 回归
- [ ] `subProfileId<0` 旧路径回归
- [ ] 老数据阻塞/新数据阻塞回归
- [ ] 升级默认 `-1` 兼容回归

## 自检结果

| 检查项 | 结果 | 说明 |
|------|------|------|
| 源码编译 `-i` | PASS | `hb build access_token -i --fast-rebuild` 成功 |
| SDK so 设备替换 | PASS | 已按设备真实路径替换 `libaccesstoken_sdk.z.so` / `libprivacy_sdk.z.so` |
| ATM SDK 聚焦验证 | PASS | 设备侧 `PermissionRequestToggleStatusTest.*` 与 `AccessTokenDenyTest` 相关 toggle 用例通过 |
| Privacy SDK 聚焦验证 | PASS | 设备侧 `SetPermissionUsedRecordToggleStatus001~004` 与 `PermDenyTest.SetPermissionUsedRecordToggleStatus001` 通过 |
| `201` 回归 | PASS | ATM/Privacy service 与 manager 侧用例已覆盖 `userId != 0 -> 201` |
| `subProfileId<0` 旧路径回归 | PASS | ATM/Privacy service 与存储层用例已覆盖负值归一化到旧路径 |
| 旧数据阻塞/新数据阻塞回归 | PASS | ATM/Privacy 存储层与 service 层用例已覆盖双向冲突 |
| 升级默认 `-1` 兼容回归 | PASS | ATM/Privacy 数据库升级用例与实现已验证默认 `-1` |
| `801` 回归 | PENDING | 需要结合 feature 开关关闭场景补最终对外接口回归证据 |
| 统一 `-i -t --fast-rebuild` 测试编译 | PENDING | 正在按统一命令继续收口测试构建错误并重编 |

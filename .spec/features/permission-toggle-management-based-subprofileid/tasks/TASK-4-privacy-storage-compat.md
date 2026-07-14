# 任务规格

## 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-4 |
| 标题 | Privacy 存储与数据库兼容 |
| 关联 Feature | FEAT-permission-toggle-management-based-subprofileid |
| 目标仓库 | security_access_token |
| 目标模块 | `services/privacymanager` |
| 分支 | 当前工作分支 |
| 优先级 | P0 |
| 复杂度 | 高 |
| 执行方式 | 主线程顺序执行 |

## 任务描述

### 做什么

1. Privacy 开关表新增 `sub_profile_id` 列并按升级默认 `-1` 处理。
2. 实现 `subProfileId<0` 走旧路径、旧数据阻塞新路径、新数据阻塞旧接口写入。
3. 同步缓存键和查询继承逻辑。

### 不做什么

- 不修改 ATM 存储逻辑。
- 不补全最终回归测试。

## 规格映射与边界

### AC 映射

| AC | 来源 | 验证方式 |
|----|------|----------|
| AC-2.1 | spec.md | 单测/集成 |
| AC-2.3 | spec.md | 单测 |
| AC-2.4 | spec.md | 单测/集成 |
| AC-2.5 | spec.md | 单测 |
| AC-3.1 | spec.md | 集成 |
| AC-3.2 | spec.md | 集成 |
| AC-3.3 | spec.md | 单测/集成 |

### 前置依赖

| 类型 | 编号 | 原因 |
|------|------|------|
| Task | TASK-2 | 参数规则已固化 |

### 完成判据

- Privacy DB/缓存层满足旧新模式双向阻塞。
- `sub_profile_id = -1` 升级兼容有效。

### 停止条件

- 表升级机制不支持安全加列。

## 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `services/privacymanager/src/record/*` | Privacy 存储与管理器 |
| 修改 | `services/privacymanager/src/service/*` | Privacy 服务规则接入 |
| 修改 | `services/privacymanager/test/unittest/*` | Privacy 测试 |

## 验证检查清单

- [x] 升级后历史记录按 `-1` 处理
- [x] 老数据阻塞新路径写入
- [x] 新数据阻塞旧接口写入
- [x] `subProfileId<0` 走旧路径

## 自检结果

| 检查项 | 结果 | 说明 |
|------|------|------|
| Privacy 表结构新增 `sub_profile_id` | PASS | toggle 表新增 `sub_profile_id`，建表主键扩展为 `user_id + sub_profile_id` |
| 升级默认值兼容 | PASS | 数据库版本升至 `8`，7->8 升级补列默认 `-1` |
| 旧路径/新路径双向冲突 | PASS | `ValidateUsedRecordToggleStorageModeConflict` 已按缓存维度实现 |
| 远端记录支持 `subProfileId` | PASS | `RemotePermissionRecord`、远端 DB、远端缓存清理均已带 `subProfileId` |
| 源码编译验证 | PASS | `hb build access_token -i --fast-rebuild` 成功 |
| `/system/lib` 直接替换 so | PASS | 已替换 `libprivacy_manager_service.z.so` |
| 设备侧 TDD 可执行性 | PASS | `privacy_subprofile_test` 可在设备启动并执行现有测试套 |
| `SubProfilePermissionUsedRecordToggleServiceTest` 聚焦验证 | PENDING | 当前未在现有 privacy TDD 产物中命中，需后续确认测试目标集成配置 |

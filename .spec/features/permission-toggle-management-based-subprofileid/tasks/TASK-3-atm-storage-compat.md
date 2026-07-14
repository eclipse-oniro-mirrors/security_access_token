# 任务规格

## 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-3 |
| 标题 | ATM 存储与数据库兼容 |
| 关联 Feature | FEAT-permission-toggle-management-based-subprofileid |
| 目标仓库 | security_access_token |
| 目标模块 | `services/accesstokenmanager` |
| 分支 | 当前工作分支 |
| 优先级 | P0 |
| 复杂度 | 高 |
| 执行方式 | 主线程顺序执行 |

## 任务描述

### 做什么

1. ATM 开关表新增 `sub_profile_id` 列并按升级默认 `-1` 处理。
2. 实现 `subProfileId<0` 走旧路径、旧数据阻塞新路径、新数据阻塞旧接口写入。
3. 同步缓存键和查询继承逻辑。

### 不做什么

- 不修改 Privacy 存储逻辑。
- 不补全最终回归测试。

## 规格映射与边界

### AC 映射

| AC | 来源 | 验证方式 |
|----|------|----------|
| AC-1.1 | spec.md | 单测/集成 |
| AC-1.3 | spec.md | 单测 |
| AC-1.4 | spec.md | 单测/集成 |
| AC-1.5 | spec.md | 单测 |
| AC-3.1 | spec.md | 集成 |
| AC-3.2 | spec.md | 集成 |
| AC-3.3 | spec.md | 单测/集成 |

### 前置依赖

| 类型 | 编号 | 原因 |
|------|------|------|
| Task | TASK-2 | 参数规则已固化 |

### 完成判据

- ATM DB/缓存层满足旧新模式双向阻塞。
- `sub_profile_id = -1` 升级兼容有效。

### 停止条件

- 表升级机制不支持安全加列。

## 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `services/accesstokenmanager/main/cpp/src/permission/*` | ATM 存储与管理器 |
| 修改 | `services/accesstokenmanager/main/cpp/src/service/*` | ATM 服务规则接入 |
| 修改 | `services/accesstokenmanager/test/unittest/*` | ATM 测试 |

## 验证检查清单

- [x] 升级后历史记录按 `-1` 处理
- [x] 老数据阻塞新路径写入
- [x] 新数据阻塞旧接口写入
- [x] `subProfileId<0` 走旧路径

## 自检结果

| 检查项 | 结果 | 说明 |
|------|------|------|
| ATM 表结构新增 `sub_profile_id` | PASS | 建表主键扩展为 `user_id + permission_name + sub_profile_id` |
| 升级默认值兼容 | PASS | `UpgradeFromVersion9` 对历史记录补列并默认 `-1` |
| 旧路径/新路径双向冲突 | PASS | manager 新增 legacy/subProfile 双向冲突判断 |
| 新路径查询继承旧值 | PASS | 新路径无记录且 legacy 有记录时返回 legacy 状态 |
| 源码编译验证 | PASS | `hb build access_token -i --fast-rebuild` 成功 |
| `/system/lib` 直接替换 so | PASS | `hdc shell mount -o rw,remount /` 后成功替换 `libaccesstoken_manager_service.z.so` |
| 设备侧 TDD 验证 | PASS | `/data/local/tmp/libaccesstoken_manager_service_standard_test_task3 --gtest_filter=PermissionRequestToggleManagerTest.*:SubProfilePermissionRequestToggleServiceTest.*` 通过 |

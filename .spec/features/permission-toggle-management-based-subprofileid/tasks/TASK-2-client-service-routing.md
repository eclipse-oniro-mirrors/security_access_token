# 任务规格

## 任务元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-2 |
| 标题 | Client/Service 参数与路由规则 |
| 关联 Feature | FEAT-permission-toggle-management-based-subprofileid |
| 目标仓库 | security_access_token |
| 目标模块 | `interfaces/innerkits/*`, `services/*/idl`, proxy/stub, service入口 |
| 分支 | 当前工作分支 |
| 优先级 | P0 |
| 复杂度 | 高 |
| 执行方式 | 主线程顺序执行 |

## 任务描述

### 做什么

1. InnerKit 保留 `userId` 参数并新增 `subProfileId=-1` 入参。
2. 服务入口实现 `userId==0`、`userId!=0 -> 201`、`subProfileId<0 -> 旧路径`、`subProfileId>=0 -> 校验` 规则；未定义 feature 时统一将 `subProfileId` 归一化为 `-1`。
3. IPC/proxy/stub 扩展 `subProfileId` 透传；`GetTokenIDByUserID` 链路同步扩签名，且仅 kit 层保留默认值。

### 不做什么

- 不修改具体数据库表和持久化实现。
- 不补全最终回归测试。
- TODO: `subProfileId >= 0` 的账号存在性校验依赖账号能力接入，当前阶段只预留校验入口。

## 规格映射与边界

### AC 映射

| AC | 来源 | 验证方式 |
|----|------|----------|
| AC-1.2 | spec.md | 单测 |
| AC-1.3 | spec.md | 单测 |
| AC-1.5 | spec.md | 单测 |
| AC-2.2 | spec.md | 单测 |
| AC-2.3 | spec.md | 单测 |
| AC-2.5 | spec.md | 单测 |

### 前置依赖

| 类型 | 编号 | 原因 |
|------|------|------|
| Task | TASK-1 | JS/NAPI/ANI 入口已具备 |

### 完成判据

- InnerKit/IPC/服务入口参数链路打通。
- 前置错误码与旧路径分流在服务入口可命中。

### 停止条件

- `callingUid -> userId` 解析能力在当前仓无法复用。

## 受影响文件

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 修改 | `interfaces/innerkits/accesstoken/*` | ATM InnerKit |
| 修改 | `interfaces/innerkits/privacy/*` | Privacy InnerKit |
| 修改 | `services/accesstokenmanager/idl/*` | ATM IPC |
| 修改 | `services/privacymanager/idl/*` | Privacy IPC |
| 修改 | `services/accesstokenmanager/main/cpp/src/service/*` | ATM 服务入口 |
| 修改 | `services/privacymanager/src/service/*` | Privacy 服务入口 |

## 验证检查清单

- [x] `userId==0` 解析逻辑通过
- [x] `userId!=0` 返回 `201`
- [x] `subProfileId<0` 分流到旧路径
- [x] `subProfileId>=0` 进入校验入口

## 完成证据

| 证据 | 命令/路径 | 结果 |
|------|-----------|------|
| 构建 | `hb build access_token -i --fast-rebuild` | PASS |

## 自检结论

| 项 | 结果 | 说明 |
|----|------|------|
| client / service 参数扩签 | PASS | ATM/Privacy 的 idl、service、manager 入口已扩 `subProfileId` |
| `userId != 0 -> 201` | PASS | ATM/Privacy service 入口已生效 |
| `userId == 0` 解析 | PASS | `resolvedUserId` 由 service 层解析后传入 manager |
| `subProfileId < 0` 旧路径收口 | PASS | manager / record manager 已归一化并走旧路径语义 |
| feature 关闭时服务端归一化 `subProfileId=-1` | PASS | ATM/Privacy service 入口已统一处理 |
| `subProfileId >= 0` 校验入口 | PASS | `ValidateSubProfileIdForToggle` 已接入主流程 |
| `GetTokenIDByUserID` 参数扩签 | PASS | kit/client/service/IDL 已打通，且仅 kit 层保留默认值 |
| 真实账号存在性校验 | PENDING | TODO: 依赖账号能力接入后补充实现 |
| 单测/回归测试证据 | PENDING | 归属 `TASK-5` |

说明：`TASK-2` 当前可视为实现层完成并具备编译通过证据，但 `subProfileId >= 0` 的真实账号存在性校验仍待后续能力接入，测试证据仍待 `TASK-5` 补齐。

# 执行计划

## Plan 元数据

| 字段 | 内容 |
|------|------|
| Plan ID | PLAN-permission-toggle-management-based-subprofileid |
| 关联 Feature/Bug | FEAT-permission-toggle-management-based-subprofileid |
| 关联文档 | proposal.md / design.md / spec.md |
| 复杂度 | 标准 |
| 状态 | Draft |
| Owner | TBD |

## 输入状态

| 输入 | 路径 | 要求状态 |
|------|------|----------|
| Requirement | `[proposal.md]` | Approved |
| Design | `[design.md]` | Approved |
| Spec | `[spec.md]` | Approved |

## 受影响文件全量清单

| 仓 | 层（来自 design.md） | 文件路径 | 修改类型 | 说明 |
|----|---------------------|----------|----------|------|
| `security_access_token` | JS/ETS API | `frameworks/js/napi/accesstoken/*` | 修改 | abilityAccessCtrl NAPI 新签名与错误码透传 |
| `security_access_token` | JS/ETS API | `frameworks/js/napi/privacy/*` | 修改 | privacyManager NAPI 新签名与错误码透传 |
| `security_access_token` | JS/ETS API | `frameworks/ets/ani/accesstoken/*` | 修改 | abilityAccessCtrl ANI/ETS 新签名与错误码透传 |
| `security_access_token` | JS/ETS API | `frameworks/ets/ani/privacy/*` | 修改 | privacyManager ANI/ETS 新签名与错误码透传 |
| `security_access_token` | InnerKit | `interfaces/innerkits/accesstoken/*` | 修改 | ATM InnerKit 新增 `subProfileId=-1` 入参 |
| `security_access_token` | InnerKit | `interfaces/innerkits/privacy/*` | 修改 | Privacy InnerKit 新增 `subProfileId=-1` 入参 |
| `security_access_token` | IPC | `services/accesstokenmanager/idl/*` | 修改 | ATM IPC 透传 `subProfileId` |
| `security_access_token` | IPC | `services/privacymanager/idl/*` | 修改 | Privacy IPC 透传 `subProfileId` |
| `security_access_token` | 服务层 | `services/accesstokenmanager/main/cpp/src/service/*` | 修改 | ATM 服务入口、`callingUid` 解析、801/201/冲突/不存在错误码 |
| `security_access_token` | 服务层 | `services/privacymanager/src/service/*` | 修改 | Privacy 服务入口、`callingUid` 解析、801/201/冲突/不存在错误码 |
| `security_access_token` | 存储/缓存 | `services/accesstokenmanager/main/cpp/src/permission/*` | 修改 | ATM 开关表新增 `sub_profile_id` 列及兼容读写 |
| `security_access_token` | 存储/缓存 | `services/privacymanager/src/record/*` | 修改 | Privacy 开关表新增 `sub_profile_id` 列及兼容读写 |
| `security_access_token` | 测试 | `interfaces/innerkits/*/test/*` | 修改 | InnerKit 规则与错误码测试 |
| `security_access_token` | 测试 | `services/*/test/unittest/*` | 修改 | 服务、存储、数据库兼容与回归测试 |

**检查项：**
- [x] design.md 调用链每一层都有对应文件列出
- [x] 每个文件修改类型和职责说明明确
- [x] 无映射行的层意味着设计到实现的翻译缺失，需回溯补充 design.md

## AC 到 Task 追溯

| AC | 来源 | Task | 验证方式 | 覆盖？ |
|----|------|------|----------|--------|
| AC-1.1, AC-2.1 | spec.md | TASK-1, TASK-2, TASK-3, TASK-4 | 单测/集成 | 是 |
| AC-1.2, AC-2.2 | spec.md | TASK-1, TASK-2 | 单测 | 是 |
| AC-1.3, AC-2.3 | spec.md | TASK-2, TASK-3, TASK-4 | 单测 | 是 |
| AC-1.4, AC-2.4 | spec.md | TASK-2, TASK-3, TASK-4 | 单测/集成 | 是 |
| AC-1.5, AC-2.5 | spec.md | TASK-2, TASK-3, TASK-4 | 单测 | 是 |
| AC-3.1, AC-3.2 | spec.md | TASK-3, TASK-4, TASK-5 | 集成 | 是 |
| AC-3.3 | spec.md | TASK-3, TASK-4, TASK-5 | 单测/集成 | 是 |
| AC-3.4, AC-3.5 | spec.md | TASK-1, TASK-5 | 回归 | 是 |

## 首批实现边界

**首批必须实现：** JS/ANI 新签名、InnerKit/IPC 扩展、ATM/Privacy 存储兼容、错误码透传、数据库新增列、最小回归测试  
**可后置：** 更广泛的产品级集成验证、额外性能观察  
**不建议延后：** `sub_profile_id=-1` 升级兼容、801/201/冲突/不存在错误码分支、旧新模式双向阻塞

## 阶段计划

| 阶段 | 目标 | 关键 Task | 结束门槛 | 最小验证 |
|------|------|-----------|----------|----------|
| Phase-1 | 接口接线层完成 | TASK-1, TASK-2 | 新签名、InnerKit/IPC、服务入口参数链路编译通过 | 相关单测可编译 |
| Phase-2 | 规则与存储层完成 | TASK-3, TASK-4 | ATM/Privacy 数据库兼容与冲突规则完成 | 存储/服务单测通过 |
| Phase-3 | 测试闭环 | TASK-5 | 关键 AC 全覆盖并有 fresh evidence | 单测/回归命令通过 |

## 禁止项

- [x] 没有 TBD / TODO / 占位符
- [x] 没有模糊指令
- [x] 没有跨 Task 隐式依赖
- [x] 没有要求 Agent 自行寻找未列出的上下文文件
- [x] 没有无验证方式的 AC
- [x] 没有“参考 Task-N 实现”式依赖

## Task 列表

| Task ID | 目标 | 文件范围 | AC 映射 | 前置依赖 | 完成判据 | 验证命令 |
|---------|------|----------|---------|----------|----------|----------|
| TASK-1 | 实现 NAPI/ANI 同名新签名扩展与 801/错误码透传 | `frameworks/js/napi/*`, `frameworks/ets/ani/*` | AC-1.1, AC-1.2, AC-2.1, AC-2.2, AC-3.4 | 无 | 新签名可编译，错误码透传链路就位 | 相关单测编译/执行 |
| TASK-2 | 实现 client / service 框架层参数、`callingUid`、`userId==0` 和 `subProfileId<0` 分流规则 | `interfaces/innerkits/*`, `services/*/idl`, proxy/stub, service入口 | AC-1.2, AC-1.3, AC-1.5, AC-2.2, AC-2.3, AC-2.5 | TASK-1 | 参数规则和错误码规则在框架层闭环 | InnerKit/服务单测 |
| TASK-3 | 实现 ATM 开关存储逻辑和数据库/缓存兼容处理 | `services/accesstokenmanager` 存储与服务相关文件 | AC-1.1, AC-1.3, AC-1.4, AC-1.5, AC-3.1, AC-3.2, AC-3.3 | TASK-2 | ATM 新旧模式、升级列、冲突和旧路径分流完整生效 | ATM 单测/集成 |
| TASK-4 | 实现 Privacy 开关存储逻辑和数据库/缓存兼容处理 | `services/privacymanager` 存储与服务相关文件 | AC-2.1, AC-2.3, AC-2.4, AC-2.5, AC-3.1, AC-3.2, AC-3.3 | TASK-2 | Privacy 新旧模式、升级列、冲突和旧路径分流完整生效 | Privacy 单测/集成 |
| TASK-5 | 补充单测和回归测试 | `interfaces/innerkits/*/test/*`, `services/*/test/*` | AC-3.2, AC-3.4, AC-3.5 | TASK-3, TASK-4 | AC 关键路径均有 fresh evidence | 单测/回归命令 |

## Task 详情

### TASK-1: NAPI/ANI 新签名与错误码透传

| 字段 | 内容 |
|------|------|
| 任务目标 | 为 abilityAccessCtrl 和 privacyManager 增加同名 `subProfileId` 新签名，并把 `801`、subProfile 不存在错误码、storage mode conflict 错误码正确透传到 JS/ETS |
| AC 映射 | AC-1.1, AC-1.2, AC-2.1, AC-2.2, AC-3.4 |
| 前置依赖 | design.md/spec.md Approved |
| 非目标 | 不实现数据库逻辑；不修改存储规则 |
| 完成判据 | JS/ETS API 声明、NAPI/ANI 接线和错误码透传可编译并可被测试调用 |
| 停止条件 | 若同名签名在 ETS/NAPI 层无法表达，需要先回传修订设计 |

### TASK-2: Client/Service 框架层规则

| 字段 | 内容 |
|------|------|
| 任务目标 | 在 InnerKit、IPC、服务入口层落实 `userId==0`、`201`、`subProfileId<0` 走旧路径、`subProfileId>=0` 校验归属等前置规则 |
| AC 映射 | AC-1.2, AC-1.3, AC-1.5, AC-2.2, AC-2.3, AC-2.5 |
| 前置依赖 | TASK-1 |
| 非目标 | 不实现具体 ATM/Privacy 表结构改动 |
| 完成判据 | 参数和错误码规则在服务入口闭环，ATM/Privacy 可共享同类规则 |
| 停止条件 | 若 `callingUid -> userId` 解析能力缺失，需要先回传 |

### TASK-3: ATM 存储与数据库兼容

| 字段 | 内容 |
|------|------|
| 任务目标 | 完成 ATM 开关表新增 `sub_profile_id` 列、默认 `-1` 升级兼容、旧新模式双向阻塞、缓存同步和查询继承 |
| AC 映射 | AC-1.1, AC-1.3, AC-1.4, AC-1.5, AC-3.1, AC-3.2, AC-3.3 |
| 前置依赖 | TASK-2 |
| 非目标 | 不修改 Privacy 存储逻辑 |
| 完成判据 | ATM 在 DB/缓存层满足旧路径、`subProfileId` 新路径、冲突错误码和升级列兼容要求 |
| 停止条件 | 若现有表结构/升级框架不支持安全扩列，需要回传修订 |

### TASK-4: Privacy 存储与数据库兼容

| 字段 | 内容 |
|------|------|
| 任务目标 | 完成 Privacy 开关表新增 `sub_profile_id` 列、默认 `-1` 升级兼容、旧新模式双向阻塞、缓存同步和查询继承 |
| AC 映射 | AC-2.1, AC-2.3, AC-2.4, AC-2.5, AC-3.1, AC-3.2, AC-3.3 |
| 前置依赖 | TASK-2 |
| 非目标 | 不修改 ATM 存储逻辑 |
| 完成判据 | Privacy 在 DB/缓存层满足旧路径、`subProfileId` 新路径、冲突错误码和升级列兼容要求 |
| 停止条件 | 若现有表结构/升级框架不支持安全扩列，需要回传修订 |

### TASK-5: 单测与回归测试

| 字段 | 内容 |
|------|------|
| 任务目标 | 为 NAPI/ANI、InnerKit、服务、数据库兼容和车机/非车机场景补齐单测与回归测试证据 |
| AC 映射 | AC-3.2, AC-3.4, AC-3.5 及前述关键规则 |
| 前置依赖 | TASK-3, TASK-4 |
| 非目标 | 不新增与本需求无关的测试框架能力 |
| 完成判据 | 关键 AC 对应测试执行并记录 fresh evidence |
| 停止条件 | 若关键测试依赖外部产品配置无法在本仓完成，需要回传说明缺口 |

## Plan 自审清单

- [x] 每个 P0/P1 AC 至少映射到一个 Task
- [x] 每个 Task 文件范围明确
- [x] 每个 Task 明确前置依赖、非目标、完成判据和停止条件
- [x] 每个 Task 有验证命令
- [x] Task 粒度形成能力闭环
- [x] 没有 TBD/TODO/占位符
- [x] 没有要求 Agent 自行寻找未列出的上下文
- [x] 交接信息自包含（对当前阶段已足够）
- [x] 每个 Task 验证在完成时立即执行并记录证据
- [x] 超 3000 行阈值的实现已按能力边界拆分

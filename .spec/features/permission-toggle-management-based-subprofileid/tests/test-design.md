# 测试设计

## 说明

- 本文档基于 [spec.md](../spec.md) 输出测试设计。
- 本文档只基于规格，不基于当前实现细节推导测试。
- 本文档覆盖 ATM、Privacy、JS/NAPI/ANI、InnerKit、服务、数据库升级、多设备适配等测试设计。
- 本文档用于定义测试覆盖面、层级和分组；逐条可执行测试规格见 [test-cases.md](./test-cases.md)。
- 测试用例拆分遵循当前变更约束：正常功能优先放在 kit，涉及 account 归属和参数异常的场景优先放在服务端。

## 完整测试设计表

| 编号 | 规格映射 | 测试层级 | 测试主题 | 前置条件 | 测试输入 / 步骤 | 预期结果 |
|---|---|---|---|---|---|---|
| TC-01 | AC-1.1, BR-1, FR-1 | JS/NAPI/ANI/集成 | ATM 新签名按 `userId + subProfileId + permissionName` 维度设置 | 车机；`ACCESS_TOKEN_SUPPORT_SUBPROFILE` 开启；存在合法 `subProfileId` | 调用 JS 新签名 `setPermissionRequestToggleStatus(permissionName, status, subProfileId)`，随后查询同一 `subProfileId` | 仅该 `subProfileId` 对应权限状态被设置；查询返回新值 |
| TC-02 | AC-2.1, BR-1, FR-2 | JS/NAPI/ANI/集成 | Privacy 新签名按 `userId + subProfileId` 维度设置 | 车机；feature 开启；存在合法 `subProfileId` | 调用 JS 新签名 `setPermissionUsedRecordToggleStatus(status, subProfileId)`，随后查询同一 `subProfileId` | 仅该 `subProfileId` 对应记录开关被设置；查询返回新值 |
| TC-03 | AC-1.2, BR-2, VM-1 | JS/NAPI/ANI/服务 | ATM JS 新路径通过 `callingUid` 解析 `userId` | 车机；feature 开启；测试进程运行在确定 `userId` 下 | 不传 `userId`，仅传 `subProfileId` 调用 JS 新签名 | 服务端按 `callingUid` 解析当前 `userId`；set/get 落在解析出的用户维度；不写入 `userId=0` 或其他用户维度 |
| TC-04 | AC-2.2, BR-2, VM-1 | JS/NAPI/ANI/服务 | Privacy JS 新路径通过 `callingUid` 解析 `userId` | 车机；feature 开启；测试进程运行在确定 `userId` 下 | 不传 `userId`，仅传 `subProfileId` 调用 JS 新签名 | 服务端按 `callingUid` 解析当前 `userId`；set/get 落在解析出的用户维度；不写入 `userId=0` 或其他用户维度 |
| TC-05 | AC-1.3, BR-3, EX-2, VM-2 | 服务/集成 | ATM 非法 `subProfileId` 返回模块专用错误码，JS/ANI 映射 `12100001` | 车机；feature 开启；当前 `userId` 下不存在该 `subProfileId` | 调用 ATM 新路径 set/get | InnerKit 返回 `ERR_PERMISSION_REQUEST_TOGGLE_SUBPROFILE_NOT_EXIST`；JS/ANI 返回 `12100001` |
| TC-06 | AC-2.3, BR-3, EX-2, VM-2 | 服务/集成 | Privacy 非法 `subProfileId` 返回模块专用错误码，JS/ANI 映射 `12100001` | 车机；feature 开启；当前 `userId` 下不存在该 `subProfileId` | 调用 Privacy 新路径 set/get | InnerKit 返回 `ERR_PERMISSION_USED_RECORD_SUBPROFILE_NOT_EXIST`；JS/ANI 返回 `12100001` |
| TC-07 | AC-1.4, BR-4, EX-3, VM-3 | 存储/服务/集成 | ATM 老数据阻塞新路径 `status=true` | 车机；feature 开启；当前 `userId` 已存在旧路径数据 | 对任一合法 `subProfileId` 调用新路径 set `true` | 返回 `ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT` |
| TC-08 | AC-1.4, BR-4, EX-3, VM-3 | 存储/服务/集成 | ATM 老数据阻塞新路径 `status=false` | 车机；feature 开启；当前 `userId` 已存在旧路径数据 | 对任一合法 `subProfileId` 调用新路径 set `false` | 返回 `ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT` |
| TC-09 | AC-2.4, BR-4, EX-3, VM-3 | 存储/服务/集成 | Privacy 老数据阻塞新路径 `status=true` | 车机；feature 开启；当前 `userId` 已存在旧路径数据 | 对任一合法 `subProfileId` 调用新路径 set `true` | 返回 `ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT` |
| TC-10 | AC-2.4, BR-4, EX-3, VM-3 | 存储/服务/集成 | Privacy 老数据阻塞新路径 `status=false` | 车机；feature 开启；当前 `userId` 已存在旧路径数据 | 对任一合法 `subProfileId` 调用新路径 set `false` | 返回 `ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT` |
| TC-11 | AC-1.5, BR-6, FR-6, VM-5 | InnerKit/服务 | ATM `subProfileId<0` 按旧路径处理 | 车机；feature 开启 | InnerKit 调用 set/get，传 `subProfileId=-1`、`-2` 等负值 | 统一按旧路径处理，不进入新路径校验与新维度存储 |
| TC-12 | AC-2.5, BR-6, FR-6, VM-5 | InnerKit/服务 | Privacy `subProfileId<0` 按旧路径处理 | 车机；feature 开启 | InnerKit 调用 set/get，传负值 `subProfileId` | 统一按旧路径处理，不进入新路径校验与新维度存储 |
| TC-13 | AC-3.1, BR-4, BR-7, FR-3, FR-7 | 存储/查询 | ATM 新路径查询继承旧路径值 | 车机；feature 开启；当前 `userId` 仅存在旧路径记录 | 对任一合法 `subProfileId` 调用新路径 get | 返回旧路径状态值 |
| TC-14 | AC-3.1, BR-4, BR-7, FR-3, FR-7 | 存储/查询 | Privacy 新路径查询继承旧路径值 | 车机；feature 开启；当前 `userId` 仅存在旧路径记录 | 对任一合法 `subProfileId` 调用新路径 get | 返回旧路径状态值 |
| TC-15 | AC-3.2, BR-7, BR-8, FR-4, RC-1, VM-6 | 集成 | ATM 旧路径清理后允许切换新路径 | 车机；feature 开启；先有旧路径数据 | 先通过旧路径完成数据库和缓存清理，再对合法 `subProfileId` 调用新路径 set/get | 新路径设置成功，查询成功，不再返回冲突 |
| TC-16 | AC-3.2, BR-7, BR-8, FR-4, RC-1, VM-6 | 集成 | Privacy 旧路径清理后允许切换新路径 | 车机；feature 开启；先有旧路径数据 | 先通过旧路径完成数据库和缓存清理，再对合法 `subProfileId` 调用新路径 set/get | 新路径设置成功，查询成功，不再返回冲突 |
| TC-16A | BR-10, FR-10 | 存储/服务 | ATM 默认状态不落库 | 车机；feature 开启；选择 `APP_TRACKING_CONSENT` 和普通权限各一项 | 分别设置为非默认值再恢复默认值 | 非默认值写入状态记录；恢复默认值删除目标维度状态记录，查询返回默认状态 |
| TC-16B | BR-10, FR-10 | 存储/服务 | Privacy 默认状态不落库 | 车机；feature 开启 | 设置 `false` 后再设置 `true` | `false` 写入状态记录；恢复 `true` 删除目标维度状态记录，查询返回 `true` |
| TC-17 | AC-3.3, BR-5, EX-4, VM-4 | 存储/服务/集成 | ATM 新数据存在时旧接口设置被阻塞 | 车机；feature 开启；当前 `userId` 已存在 `subProfileId>=0` 新数据 | 调用不传 `subProfileId` 的旧接口 set | 返回 `ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT` |
| TC-18 | AC-3.3, BR-5, EX-4, VM-4 | 存储/服务/集成 | Privacy 新数据存在时旧接口设置被阻塞 | 车机；feature 开启；当前 `userId` 已存在 `subProfileId>=0` 新数据 | 调用不传 `subProfileId` 的旧接口 set | 返回 `ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT` |
| TC-19 | AC-3.4, BR-1, BR-9, EX-0, VM-7 | JS/NAPI/ANI 回归 | feature 未定义时 ATM 新签名返回 `801` | `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 未定义 | 调用 JS/ETS/ANI 新签名 `set/getPermissionRequestToggleStatus(..., subProfileId)` | 返回 `801`；不落入 InnerKit 旧路径写入 |
| TC-20 | AC-3.4, BR-1, BR-9, EX-0, VM-7 | JS/NAPI/ANI 回归 | feature 未定义时 Privacy 新签名返回 `801` | `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 未定义 | 调用 JS/ETS/ANI 新签名 `set/getPermissionUsedRecordToggleStatus(..., subProfileId)` | 返回 `801`；不落入 InnerKit 旧路径写入 |
| TC-21 | AC-3.5, BR-1, BR-9, VM-8 | 回归 | feature 未定义时 ATM 旧 API 保持旧行为 | `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 未定义；当前 `userId` 不存在任何新数据 | 调用旧 JS API / InnerKit 旧路径；InnerKit 显式传 `subProfileId>=0` 时按旧路径归一化 | 旧接口 set/get 成功并按原 `userId + permissionName` 维度返回写入值；不返回 `801`、subProfile 不存在或 storage conflict |
| TC-22 | AC-3.5, BR-1, BR-9, VM-8 | 回归 | feature 未定义时 Privacy 旧 API 保持旧行为 | `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 未定义；当前 `userId` 不存在任何新数据 | 调用旧 JS API / InnerKit 旧路径；InnerKit 显式传 `subProfileId>=0` 时按旧路径归一化 | 旧接口 set/get 成功并按原 `userId` 维度返回写入值；不返回 `801`、subProfile 不存在或 storage conflict |
| TC-23 | BR-2, EX-1 | InnerKit/服务 | 非 JS 新路径 `userId!=0` 返回 `201`（ATM） | 车机；feature 开启 | InnerKit/service 直接调用新路径，传 `userId=1` | 返回 `201` |
| TC-24 | BR-2, EX-1 | InnerKit/服务 | 非 JS 新路径 `userId!=0` 返回 `201`（Privacy） | 车机；feature 开启 | InnerKit/service 直接调用新路径，传 `userId=1` | 返回 `201` |
| TC-25 | BR-7, BR-8 | 数据库升级 | ATM 历史数据升级后默认 `sub_profile_id=-1` | 升级前存在旧表旧记录 | 执行 DB 升级 | 历史记录被视为旧路径数据，读取/冲突行为符合旧路径语义 |
| TC-26 | BR-7, BR-8 | 数据库升级 | Privacy 历史数据升级后默认 `sub_profile_id=-1` | 升级前存在旧表旧记录 | 执行 DB 升级 | 历史记录被视为旧路径数据，读取/冲突行为符合旧路径语义 |
| TC-27 | API 变更分析 | InnerKit/服务 | `AccessTokenKit::GetTokenIDByUserID(userId, tokenIdList, subProfileId)` feature on | 车机；feature 开启；存在合法 `subProfileId` | 传 `subProfileId>=0` 调用接口 | 返回属于当前 `userId + subProfileId` 范围的 tokenId 集合 |
| TC-28 | API 变更分析 | InnerKit/服务 | `AccessTokenKit::GetTokenIDByUserID(userId, tokenIdList, subProfileId)` feature off | `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 未定义 | 传 `subProfileId>=0` 调用接口 | 内部按旧路径处理，不引入 `subProfileId` 过滤语义；结果与旧签名一致 |
| TC-29 | NFR-安全 | 安全回归 | ATM 禁止跨 profile 读写 | 车机；feature 开启；`subProfileId` 属于其他 `userId` | 调用新路径 set/get | 不允许成功；返回 subProfile 不存在错误码 |
| TC-30 | NFR-安全 | 安全回归 | Privacy 禁止跨 profile 读写 | 车机；feature 开启；`subProfileId` 属于其他 `userId` | 调用新路径 set/get | 不允许成功；返回 subProfile 不存在错误码 |
| TC-31 | 多设备适配 | 回归 | feature 未定义产品新签名不可用（ATM） | `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 未定义 | 调用 ATM 新签名 | 返回 `801`；旧路径保持原行为 |
| TC-32 | 多设备适配 | 回归 | feature 未定义产品新签名不可用（Privacy） | `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 未定义 | 调用 Privacy 新签名 | 返回 `801`；旧路径保持原行为 |
| TC-33 | 多设备适配 | 集成 | 车机端新签名可用并受兼容规则约束（ATM） | 车机；feature 开启 | 分别验证合法 `subProfileId`、老数据阻塞、新数据阻塞、负值旧路径 | 合法新路径 set/get 返回写入值且不同 `subProfileId` 隔离；旧数据存在时新路径 set 返回 `ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT`；新数据存在时旧接口 set 返回同一冲突码；负值 `subProfileId` 按旧路径处理 |
| TC-34 | 多设备适配 | 集成 | 车机端新签名可用并受兼容规则约束（Privacy） | 车机；feature 开启 | 分别验证合法 `subProfileId`、老数据阻塞、新数据阻塞、负值旧路径 | 合法新路径 set/get 返回写入值且不同 `subProfileId` 隔离；旧数据存在时新路径 set 返回 `ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT`；新数据存在时旧接口 set 返回同一冲突码；负值 `subProfileId` 按旧路径处理 |
| TC-35 | 扩展规则 | 远端记录/集成 | Privacy remote 记录按 `userId + subProfileId` 维度隔离 | 车机；feature 开启；存在两个不同 `subProfileId` | 分别写入 remote record，再查询/清理/合并 | 查询 A 只返回 A 的 remote record，查询 B 只返回 B 的 remote record；删除 A 后 B 仍可查询；合并统计不跨 `subProfileId` 聚合 |
| TC-36 | 问题定位 | 错误码回归 | JS/ANI/native 错误码可区分 | 对应触发 `801`、`201`、subProfile 不存在、storage conflict | 分别调用相关接口 | feature off 返回 `801`；非 JS 新路径 `userId!=0` 返回 `201`；非法 `subProfileId` 返回模块对应不存在错误码；存储模式冲突返回模块对应 storage conflict 错误码，接口层映射不互相覆盖 |
| TC-37 | BR-7, BR-8, RC-1 | OTA/升级手工 | ATM OTA 升级后旧数据兼容与切换 | 升级前设备存在旧路径 toggle 数据 | 执行 OTA 升级，再分别验证旧路径查询、新路径继承、旧数据清理后切换新路径 | 升级后旧数据按 `sub_profile_id=-1` 语义保留；新路径先继承旧值，清理后可切换新路径 |
| TC-38 | BR-7, BR-8, RC-1 | OTA/升级手工 | Privacy OTA 升级后旧数据兼容与切换 | 升级前设备存在旧路径 record toggle 数据 | 执行 OTA 升级，再分别验证旧路径查询、新路径继承、旧数据清理后切换新路径 | 升级后旧数据按 `sub_profile_id=-1` 语义保留；新路径先继承旧值，清理后可切换新路径 |

## 最小验证分组

| 分组 | 目标 | 推荐优先级 |
|---|---|---|
| G1 | `801` feature 未定义新签名回归 | P0 |
| G2 | `201` 非 JS 新路径非法 `userId` 回归 | P0 |
| G3 | 老数据阻塞新写 / 新数据阻塞旧写 | P0 |
| G4 | `subProfileId<0` 旧路径回归 | P0 |
| G5 | 升级后 `sub_profile_id=-1` 兼容 | P0 |
| G6 | `GetTokenIDByUserID(..., subProfileId)` 新签名 | P1 |
| G7 | Privacy remote `userId + subProfileId` 维度专项回归 | P1 |
| G8 | OTA 升级兼容与切换 | P0 |

## 手工测试说明

- TC-37 ATM OTA 升级兼容场景：
  - 原因：依赖真实升级前数据、数据库迁移和 OTA 前后版本切换，仓内单测难以完整复现整机升级过程。
  - 结论：标记为手工测试，允许先以 DB 升级单测替代部分逻辑验证，再由设备侧 OTA 回归收口。
- TC-38 Privacy OTA 升级兼容场景：
  - 原因：依赖真实升级前 record toggle 数据、数据库迁移和 OTA 前后版本切换，仓内单测难以完整复现整机升级过程。
  - 结论：标记为手工测试，允许先以 DB 升级单测替代部分逻辑验证，再由设备侧 OTA 回归收口。

## 测试设计实现状态

状态说明：

- `已落代码`：当前仓内已存在可对应到该测试点的 C++ 单测用例。
- `部分落代码`：当前仓内已有相关分支或子场景用例，但未完整覆盖测试点全部规格。
- `仅用例设计`：已在 [test-cases.md](./test-cases.md) 展开完整测试步骤和预期结果，但尚未落测试代码。
- `宏分支自动化`：通过 `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 开启/未定义两种构建分别编译运行 `#ifdef/#else` 分支用例。
- `构建矩阵/手工`：依赖 OTA 环境或真实升级前后版本切换，不适合只用当前单一单测二进制表达。
- 用例预期以 [spec.md](../spec.md) 为准；若当前实现不满足规格，测试应按规格预期失败并暴露差距。

| 编号 | 当前覆盖方式 | 当前可见代码用例 / 说明 | 规格预期 |
|---|---|---|---|
| TC-01 | 已落代码 | `SetPermissionRequestToggleStatusWithSubProfileId003` 覆盖 ATM 两个合法 `subProfileId` 的正向隔离 | 同一 `userId + permissionName` 下，不同 `subProfileId` 的状态互不串扰 |
| TC-02 | 已落代码 | `SetPermissionUsedRecordToggleStatusWithSubProfileId001` 覆盖 Privacy 两个合法 `subProfileId` 的正向隔离 | 同一 `userId` 下，不同 `subProfileId` 的记录开关状态互不串扰 |
| TC-03 | 已落代码 | `SetToggleStatusWithResolvedUserId001`, `GetToggleStatusWithResolvedUserId001` | `userId=0` 时服务端按 `callingUid` 解析真实用户维度，set/get 进入解析后的用户 |
| TC-04 | 已落代码 | `SetToggleStatusWithResolvedUserId001`, `GetToggleStatusWithResolvedUserId001` | `userId=0` 时服务端按 `callingUid` 解析真实用户维度，set/get 进入解析后的用户 |
| TC-05 | 已落代码 | `SetPermissionRequestToggleStatusWithSubProfileId005`, `SetToggleStatusWithSubProfileIdNotExist001`, `GetToggleStatusWithSubProfileIdNotExist001` | `subProfileId` 不属于当前用户时，ATM set/get 返回 `ERR_PERMISSION_REQUEST_TOGGLE_SUBPROFILE_NOT_EXIST` |
| TC-06 | 已落代码 | `SetPermissionUsedRecordToggleStatusWithSubProfileId003`, `SetToggleStatusWithSubProfileIdNotExist001`, `GetToggleStatusWithSubProfileIdNotExist001` | `subProfileId` 不属于当前用户时，Privacy set/get 返回 `ERR_PERMISSION_USED_RECORD_SUBPROFILE_NOT_EXIST` |
| TC-07 | 已落代码 | `PermissionRequestToggleStatusWithSubProfileIdConflict001`, `SetPermissionRequestToggleStatusWithSubProfileId001` | 旧路径数据存在时，ATM 新路径 set `true` 返回 `ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT` |
| TC-08 | 已落代码 | `PermissionRequestToggleStatusWithSubProfileIdConflict001`, `SetPermissionRequestToggleStatusWithSubProfileId001` | 旧路径数据存在时，ATM 新路径 set `false` 返回 `ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT` |
| TC-09 | 已落代码 | `SetPermissionUsedRecordToggleStatusWithSubProfileIdConflict001`, `SetPermissionUsedRecordToggleStatusWithSubProfileId002` | 旧路径数据存在时，Privacy 新路径 set `true` 返回 `ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT` |
| TC-10 | 已落代码 | `SetPermissionUsedRecordToggleStatusWithSubProfileIdConflict001`, `SetPermissionUsedRecordToggleStatusWithSubProfileId002` | 旧路径数据存在时，Privacy 新路径 set `false` 返回 `ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT` |
| TC-11 | 已落代码 | `PermissionRequestToggleStatusWithNegativeSubProfileId001`, `SetToggleStatusWithNegativeSubProfileId001`, `GetToggleStatusWithNegativeSubProfileId001` | ATM `subProfileId<0` 统一按旧路径处理，不进入 `subProfileId` 归属校验 |
| TC-12 | 已落代码 | `SetPermissionUsedRecordToggleStatusWithNegativeSubProfileId001`, `UpdatePermUsedRecToggleStatusMapWithNegativeSubProfileId001`, `SetToggleStatusWithNegativeSubProfileId001` | Privacy `subProfileId<0` 统一按旧路径处理，不进入 `subProfileId` 归属校验 |
| TC-13 | 已落代码 | `PermissionRequestToggleStatusWithSubProfileIdConflict001`, `GetPermissionRequestToggleStatusWithSubProfileId001` | ATM 新路径读取仅存在旧路径数据时返回旧路径状态值 |
| TC-14 | 已落代码 | `SetPermissionUsedRecordToggleStatusWithSubProfileIdConflict001`, `GetPermissionUsedRecordToggleStatus` 规格对齐 | Privacy 新路径读取仅存在旧路径数据时返回旧路径状态值 |
| TC-15 | 已落代码 | `SetPermissionRequestToggleStatusWithSubProfileId004` | ATM 旧路径数据库和缓存清理后，新路径 set/get 成功且不再返回冲突 |
| TC-16 | 已落代码 | `SetPermissionUsedRecordToggleStatusWithSubProfileId002` | Privacy 旧路径数据库和缓存清理后，新路径 set/get 成功且不再返回冲突 |
| TC-17 | 已落代码 | `PermissionRequestToggleStatusWithSubProfileIdConflict002`, `SetPermissionRequestToggleStatusWithSubProfileId002`, `GetPermissionRequestToggleStatusWithSubProfileId003` | 新路径数据存在时，ATM 旧接口设置返回 `ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT` |
| TC-18 | 已落代码 | `SetPermissionUsedRecordToggleStatusWithSubProfileIdConflict002` | 新路径数据存在时，Privacy 旧接口设置返回 `ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT` |
| TC-19 | 宏分支自动化 | `PermissionRequestToggleStatusWithoutSubProfileFeature002` 覆盖 ATM capability-not-support 到 JS/ANI `801` 映射；NAPI/ANI feature off 执行分支随 feature off 构建编译 | feature 未定义时 ATM 新签名返回 `801` |
| TC-20 | 宏分支自动化 | Privacy NAPI/ANI feature off 执行分支随 feature off 构建编译；错误码映射分支返回 JS/ANI `801` | feature 未定义时 Privacy 新签名返回 `801` |
| TC-21 | 宏分支自动化 | `PermissionRequestToggleStatusWithoutSubProfileFeature001` 覆盖 ATM feature off 下 `subProfileId>=0` 归一化到旧路径 | feature 未定义时 ATM 旧 API 保持原有 `userId` 语义，不引入 `subProfileId` |
| TC-22 | 宏分支自动化 | `SetPermissionUsedRecordToggleStatusWithoutSubProfileFeature001` 覆盖 Privacy feature off 下 `subProfileId>=0` 归一化到旧路径 | feature 未定义时 Privacy 旧 API 保持原有 `userId` 语义，不引入 `subProfileId` |
| TC-23 | 已落代码 | `SetToggleStatusWithSubProfileIdRequiresZeroUserId001`, `GetToggleStatusWithSubProfileIdRequiresZeroUserId001` | ATM 非 JS 新路径传 `userId!=0` 返回 `201` |
| TC-24 | 已落代码 | `SetToggleStatusWithSubProfileIdRequiresZeroUserId001`, `GetToggleStatusWithSubProfileIdRequiresZeroUserId001` | Privacy 非 JS 新路径传 `userId!=0` 返回 `201` |
| TC-25 | 仅用例设计 | [test-cases.md](./test-cases.md) 已展开 DB 升级步骤和预期 | ATM 历史数据升级后按 `sub_profile_id=-1` 旧路径语义生效 |
| TC-26 | 仅用例设计 | [test-cases.md](./test-cases.md) 已展开 DB 升级步骤和预期 | Privacy 历史数据升级后按 `sub_profile_id=-1` 旧路径语义生效 |
| TC-27 | 部分落代码 | `GetTokenIDByUserID001` 覆盖旧签名基础行为；feature on `subProfileId` 过滤在 [test-cases.md](./test-cases.md) 展开 | feature on 时返回当前 `userId + subProfileId` 范围内 tokenId 集合 |
| TC-28 | 宏分支自动化 | `GetTokenIDByUserIDWithoutSubProfileFeature001` 覆盖 feature off 下带 `subProfileId` 调用结果与旧签名一致 | feature off 时 `GetTokenIDByUserID(..., subProfileId)` 按旧路径处理，不引入过滤语义 |
| TC-29 | 已落代码 | `SetPermissionRequestToggleStatusWithSubProfileId005`, service not-exist 分支用例 | ATM 禁止跨 profile 读写，返回 `ERR_PERMISSION_REQUEST_TOGGLE_SUBPROFILE_NOT_EXIST` |
| TC-30 | 已落代码 | `SetPermissionUsedRecordToggleStatusWithSubProfileId003`, service not-exist 分支用例 | Privacy 禁止跨 profile 读写，返回 `ERR_PERMISSION_USED_RECORD_SUBPROFILE_NOT_EXIST` |
| TC-31 | 宏分支自动化 | 与 TC-19/TC-21 共用 feature off 宏分支，验证未定义 feature 产品的 ATM 新签名不可用、旧路径兼容 | feature 未定义产品调用 ATM 新签名返回 `801` |
| TC-32 | 宏分支自动化 | 与 TC-20/TC-22 共用 feature off 宏分支，验证未定义 feature 产品的 Privacy 新签名不可用、旧路径兼容 | feature 未定义产品调用 Privacy 新签名返回 `801` |
| TC-33 | 部分落代码 | ATM 正向隔离、旧新冲突、负值旧路径、服务错误分支均已有代码；JS/ANI 闭环在 [test-cases.md](./test-cases.md) 展开 | 车机 ATM 新签名可用，并受兼容规则完整约束 |
| TC-34 | 部分落代码 | Privacy 正向隔离、旧新冲突、负值旧路径、服务错误分支均已有代码；JS/ANI 闭环在 [test-cases.md](./test-cases.md) 展开 | 车机 Privacy 新签名可用，并受兼容规则完整约束 |
| TC-35 | 仅用例设计 | [test-cases.md](./test-cases.md) 已展开 remote record 隔离步骤和预期 | Privacy remote 记录按 `userId + subProfileId` 隔离，不串查、不串删、不误合并 |
| TC-36 | 部分落代码 | native/service 错误码分支已有代码；JS/ANI 映射在 [test-cases.md](./test-cases.md) 展开 | `801`、`201`、subProfile 不存在按接口层映射返回；新增设置接口、老设置接口和老查询接口 storage conflict 映射为 operation-not-allowed，老接口返回属于新增兼容错误；新增查询接口不返回 `12100006` |
| TC-37 | 构建矩阵/手工 | OTA 升级依赖真实升级前数据和版本切换 | ATM OTA 后旧数据按 `sub_profile_id=-1` 保留，新路径先继承旧值，旧数据清理后可切换新路径 |
| TC-38 | 构建矩阵/手工 | OTA 升级依赖真实升级前数据和版本切换 | Privacy OTA 后旧数据按 `sub_profile_id=-1` 保留，新路径先继承旧值，旧数据清理后可切换新路径 |

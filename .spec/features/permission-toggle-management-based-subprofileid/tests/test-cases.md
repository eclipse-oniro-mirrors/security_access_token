# 测试用例

## 说明

- 本文档基于 [test-design.md](./test-design.md) 和 [spec.md](../spec.md) 细化测试套规划与完整测试用例。
- 先回答“哪些测试点放在哪个测试套、覆盖什么规格”，再回答“每个测试点怎么测、预期是什么”。
- 所有用例预期结果以 [spec.md](../spec.md) 为准；当前实现不满足规格时，用例应按规格失败并暴露差距，不调整预期去适配实现。
- 按当前需求约束执行：
  - 正常功能、兼容读写、feature 未定义回归优先放在 kit 测试套。
  - `callingUid -> userId`、`subProfileId` 归属校验、`userId != 0`、底层升级兼容等异常优先放在服务端或 manager/record 测试套。
- 自动化用例执行过程中如修改 caller token、uid、系统参数、toggle 状态、数据库或缓存，必须在用例结束前恢复到进入用例前状态；无法在单测内可靠恢复的 OTA 场景标记为手工验证。

## 测试套规划

### 1. ATM Kit 测试套

- 建议文件：
  - `interfaces/innerkits/accesstoken/test/unittest/HapAttributeTest/permission_request_toggle_status_test.cpp`
  - `interfaces/innerkits/accesstoken/test/unittest/PermDenyTest/accesstoken_deny_test.cpp`
- 负责测试点：
  - TC-01 ATM 新路径按 `userId + subProfileId + permissionName` 隔离设置/查询
  - TC-07 / TC-08 ATM 老数据阻塞新路径 `true/false`
  - TC-11 ATM `subProfileId<0` 旧路径兼容
  - TC-13 ATM 新路径查询继承旧路径值
  - TC-15 ATM 旧路径清理后允许切换新路径
  - TC-17 ATM 新数据存在时旧接口写入被阻塞
  - TC-19 feature 未定义时 ATM 新签名返回 `801`
  - TC-21 feature 未定义时 ATM 旧 API 保持旧行为
  - TC-27 / TC-28 `GetTokenIDByUserID(..., subProfileId)` feature on/off
- 负责规格：
  - AC-1.1, AC-1.4, AC-1.5, AC-3.1, AC-3.2, AC-3.3, AC-3.4, AC-3.5
  - BR-1, BR-4, BR-5, BR-6, BR-9
  - FR-1, FR-3, FR-4, FR-6, FR-7

### 2. ATM Service / Manager 测试套

- 建议文件：
  - `services/accesstokenmanager/test/unittest/service/accesstoken_manager_service_test.cpp`
  - `services/accesstokenmanager/test/unittest/permission/permission_request_toggle_manager_test.cpp`
- 负责测试点：
  - TC-03 ATM JS 新路径通过 `callingUid` 解析 `userId`
  - TC-05 ATM 非法 `subProfileId` 返回不存在错误码
  - TC-23 ATM 非 JS 新路径 `userId != 0` 返回 `201`
  - TC-25 ATM 历史数据升级后默认 `sub_profile_id=-1`
  - TC-29 ATM 禁止跨 profile 读写
- 负责规格：
  - AC-1.2, AC-1.3
  - BR-2, BR-3, BR-7, BR-8
  - EX-1, EX-2
  - VM-1, VM-2

### 3. Privacy Kit 测试套

- 建议文件：
  - `interfaces/innerkits/privacy/test/unittest/src/permission_used_toggle_status_test.cpp`
  - `interfaces/innerkits/privacy/test/unittest/src/permission_deny_test.cpp`
- 负责测试点：
  - TC-02 Privacy 新路径按 `userId + subProfileId` 隔离设置/查询
  - TC-09 / TC-10 Privacy 老数据阻塞新路径 `true/false`
  - TC-12 Privacy `subProfileId<0` 旧路径兼容
  - TC-14 Privacy 新路径查询继承旧路径值
  - TC-16 Privacy 旧路径清理后允许切换新路径
  - TC-18 Privacy 新数据存在时旧接口写入被阻塞
  - TC-20 feature 未定义时 Privacy 新签名返回 `801`
  - TC-22 feature 未定义时 Privacy 旧 API 保持旧行为
- 负责规格：
  - AC-2.1, AC-2.4, AC-2.5, AC-3.1, AC-3.2, AC-3.3, AC-3.4, AC-3.5
  - BR-1, BR-4, BR-5, BR-6, BR-9
  - FR-2, FR-3, FR-4, FR-6, FR-7

### 4. Privacy Service / Record 测试套

- 建议文件：
  - `services/privacymanager/test/unittest/service/privacy_manager_service_test.cpp`
  - `services/privacymanager/test/unittest/record/permission_record_manager_test.cpp`
  - `services/privacymanager/test/unittest/record/privacy_toggle_record_test.cpp`
- 负责测试点：
  - TC-04 Privacy JS 新路径通过 `callingUid` 解析 `userId`
  - TC-06 Privacy 非法 `subProfileId` 返回不存在错误码
  - TC-24 Privacy 非 JS 新路径 `userId != 0` 返回 `201`
  - TC-26 Privacy 历史数据升级后默认 `sub_profile_id=-1`
  - TC-30 Privacy 禁止跨 profile 读写
  - TC-35 Privacy remote record 按 `userId + subProfileId` 隔离
- 负责规格：
  - AC-2.2, AC-2.3
  - BR-2, BR-3, BR-7, BR-8
  - EX-1, EX-2
  - VM-1, VM-2

### 5. 多设备/错误码回归套

- 可复用前述 kit / service 测试文件，不必新建测试基础设施。
- 负责测试点：
  - TC-31 feature 未定义产品 ATM 新签名不可用
  - TC-32 feature 未定义产品 Privacy 新签名不可用
  - TC-33 车机端 ATM 新签名行为闭环
  - TC-34 车机端 Privacy 新签名行为闭环
  - TC-36 JS/ANI/native 错误码映射可区分
- 负责手工测试点：
  - TC-37 ATM OTA 升级后旧数据兼容与切换
  - TC-38 Privacy OTA 升级后旧数据兼容与切换
- 负责规格：
  - AC-3.4, AC-3.5
  - EX-0, EX-1, EX-2, EX-3, EX-4
  - 多设备适配声明
  - 问题定位相关 NFR
  - BR-7, BR-8, RC-1

## 完整测试用例

### ATM Kit 用例

#### CASE-ATM-KIT-001 ATM 新路径按 `userId + subProfileId + permissionName` 隔离设置/查询

- 对应测试点：TC-01
- 建议测试套：ATM Kit
- 建议文件：`interfaces/innerkits/accesstoken/test/unittest/HapAttributeTest/permission_request_toggle_status_test.cpp`
- 测试规格：
  - 验证 feature 开启且 `subProfileId` 合法时，ATM 新路径按 `userId + subProfileId + permissionName` 维度独立存取。
- 前置条件：
  - 车机场景。
  - `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 开启。
  - 当前 `userId` 下存在两个合法 `subProfileId`：`subProfileIdA`、`subProfileIdB`。
  - 测试权限名为有效权限。
- 测试步骤：
  1. 调用新路径接口为 `subProfileIdA` 设置 `permissionName` 的 toggle 为 `true`。
  2. 查询 `subProfileIdA` 对应 `permissionName` 的 toggle。
  3. 查询 `subProfileIdB` 对应同一 `permissionName` 的 toggle。
  4. 调用新路径接口为 `subProfileIdA` 设置 `permissionName` 的 toggle 为 `false`。
  5. 再次查询 `subProfileIdA` 和 `subProfileIdB` 的结果。
- 预期结果：
  - 步骤 2 返回 `true`。
  - 步骤 3 返回默认值或 `subProfileIdB` 自身值，不受 `subProfileIdA` 影响。
  - 步骤 5 中 `subProfileIdA` 返回 `false`，`subProfileIdB` 结果保持不变。

#### CASE-ATM-KIT-002 ATM 老数据阻塞新路径写入 `true/false`

- 对应测试点：TC-07, TC-08
- 建议测试套：ATM Kit
- 建议文件：`interfaces/innerkits/accesstoken/test/unittest/HapAttributeTest/permission_request_toggle_status_test.cpp`
- 测试规格：
  - 验证旧 `userId` 维度数据存在时，新路径对同一用户下任意合法 `subProfileId` 的 `true/false` 写入均被阻塞。
- 前置条件：
  - 车机场景，feature 开启。
  - 当前 `userId` 已存在旧路径 toggle 数据。
  - 当前 `userId` 下存在合法 `subProfileId`。
- 测试步骤：
  1. 通过旧接口写入一条 toggle 数据。
  2. 通过新路径对该 `subProfileId` 调用 set `true`。
  3. 通过新路径对该 `subProfileId` 调用 set `false`。
  4. 通过新路径查询该 `subProfileId` 对应状态。
- 预期结果：
  - 步骤 2、3 均返回 `ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT`。
  - 步骤 4 返回旧路径继承值。
  - 不出现脏写。

#### CASE-ATM-KIT-003 ATM `subProfileId<0` 走旧路径

- 对应测试点：TC-11
- 建议测试套：ATM Kit
- 建议文件：`interfaces/innerkits/accesstoken/test/unittest/HapAttributeTest/permission_request_toggle_status_test.cpp`
- 测试规格：
  - 验证负值 `subProfileId` 不进入新路径语义，统一走旧路径。
- 前置条件：
  - 车机场景，feature 开启。
- 测试步骤：
  1. 调用扩展后的接口，传 `subProfileId=-1` 设置 toggle 为 `true`。
  2. 使用旧接口查询同一权限的 toggle。
  3. 调用扩展后的查询接口，传 `subProfileId=-2` 查询。
- 预期结果：
  - 步骤 2 返回 `true`。
  - 步骤 3 与旧接口返回一致。
  - 不触发 `subProfileId` 不存在错误码。

#### CASE-ATM-KIT-004 ATM 新路径查询继承旧路径值

- 对应测试点：TC-13
- 建议测试套：ATM Kit
- 建议文件：`interfaces/innerkits/accesstoken/test/unittest/HapAttributeTest/permission_request_toggle_status_test.cpp`
- 测试规格：
  - 验证仅存在旧路径记录时，新路径查询返回旧路径状态。
- 前置条件：
  - 车机场景，feature 开启。
  - 当前 `userId` 仅存在旧路径 toggle 数据。
- 测试步骤：
  1. 通过旧接口设置 toggle 为 `true`。
  2. 通过新路径使用合法 `subProfileId` 查询。
  3. 通过旧接口修改 toggle 为 `false`。
  4. 再次通过新路径查询。
- 预期结果：
  - 第一次新路径查询返回 `true`。
  - 第二次新路径查询返回 `false`。

#### CASE-ATM-KIT-005 ATM 旧路径清理后允许切换到新路径

- 对应测试点：TC-15
- 建议测试套：ATM Kit
- 建议文件：`interfaces/innerkits/accesstoken/test/unittest/HapAttributeTest/permission_request_toggle_status_test.cpp`
- 测试规格：
  - 验证旧路径数据库和缓存清理完成后，新路径可正常写入和查询。
- 前置条件：
  - 车机场景，feature 开启。
  - 当前 `userId` 先存在旧路径数据。
- 测试步骤：
  1. 使用旧接口写入 toggle 数据。
  2. 使用新路径对合法 `subProfileId` 写入，确认先返回冲突。
  3. 使用旧接口完成旧数据删除或清理。
  4. 再次使用新路径写入 toggle。
  5. 使用新路径查询结果。
- 预期结果：
  - 步骤 2 返回 `ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT`。
  - 步骤 4 写入成功。
  - 步骤 5 返回新写入值。

#### CASE-ATM-KIT-006 ATM 新数据存在时旧接口写入被阻塞

- 对应测试点：TC-17
- 建议测试套：ATM Kit
- 建议文件：`interfaces/innerkits/accesstoken/test/unittest/HapAttributeTest/permission_request_toggle_status_test.cpp`
- 测试规格：
  - 验证已进入新路径模式后，旧接口写入被阻塞。
- 前置条件：
  - 车机场景，feature 开启。
  - 当前 `userId` 下某合法 `subProfileId` 已存在新路径数据。
- 测试步骤：
  1. 使用新路径写入一条 toggle 数据。
  2. 调用旧接口 set `true`。
  3. 调用旧接口 set `false`。
  4. 再次使用新路径查询原数据。
- 预期结果：
  - 步骤 2、3 均返回 `ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT`。
  - 步骤 4 返回原新路径数据，未被旧接口污染。

#### CASE-ATM-KIT-007 feature 未定义时 ATM 新签名返回 `801`

- 对应测试点：TC-19
- 建议测试套：ATM Kit
- 建议文件：
  - `interfaces/innerkits/accesstoken/test/unittest/HapAttributeTest/permission_request_toggle_status_test.cpp`
  - `frameworks/js/napi/accesstoken/src/napi_atmanager.cpp`
  - `frameworks/ets/ani/accesstoken/src/ani_ability_access_ctrl.cpp`
- 测试规格：
  - 验证 `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 未定义时，ATM 新增 `subProfileId` 签名不可用并返回 `801`。
- 前置条件：
  - `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 未定义。
- 测试步骤：
  1. 以 feature off 构建编译运行 `#else` 分支。
  2. 调用或覆盖 JS/NAPI 新签名 set 执行分支。
  3. 调用或覆盖 JS/NAPI 新签名 get 执行分支。
  4. 调用或覆盖 ETS/ANI 新签名 set/get 执行分支。
  5. 校验 native capability-not-support 到 JS/ANI `801` 的错误码映射。
- 预期结果：
  - 步骤 2~4 均返回或抛出 `801`。
  - 不写入 `userId + permissionName` 旧路径，也不写入 `subProfileId` 新路径。
  - 错误码映射不退化为 `12100001`、`12100017` 或内部错误码。

#### CASE-ATM-KIT-008 feature 未定义时 ATM 旧 API 保持旧行为

- 对应测试点：TC-21
- 建议测试套：ATM Kit
- 建议文件：`interfaces/innerkits/accesstoken/test/unittest/HapAttributeTest/permission_request_toggle_status_test.cpp`
- 测试规格：
  - 验证 feature 未定义时旧接口行为不发生语义变化，InnerKit 显式传 `subProfileId>=0` 也按旧路径归一化处理。
- 前置条件：
  - `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 未定义。
  - 当前 `userId` 不存在新路径数据。
- 测试步骤：
  1. 使用带 `subProfileId>=0` 的 InnerKit 扩展签名 set `false`。
  2. 使用旧签名 get。
  3. 使用旧签名 set `true`。
  4. 使用带 `subProfileId>=0` 的 InnerKit 扩展签名 get。
- 预期结果：
  - 步骤 2 返回 `false`，说明 feature off 下带 `subProfileId` 调用被归一化到旧路径。
  - 步骤 4 返回 `true`，说明旧路径写入可被带 `subProfileId` 调用读取。
  - 不返回 `801`、不存在、冲突等新语义错误码。

#### CASE-ATM-KIT-009 `GetTokenIDByUserID(..., subProfileId)` feature on/off

- 对应测试点：TC-27, TC-28
- 建议测试套：ATM Kit
- 建议文件：`interfaces/innerkits/accesstoken/test/unittest/HapAttributeTest/permission_request_toggle_status_test.cpp`
- 测试规格：
  - 验证 feature 开启时接口按 `subProfileId` 过滤，feature 关闭时保持旧行为。
- 前置条件：
  - 准备 `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 开启和未定义两组构建。
  - 当前 `userId` 下存在合法 `subProfileId` 和可观测 token 集合。
- 测试步骤：
  1. 在 feature on 场景传合法 `subProfileId` 调用 `GetTokenIDByUserID`。
  2. 在 feature off 场景分别调用旧签名和带 `subProfileId` 扩展签名。
- 预期结果：
  - feature on 时仅返回当前 `userId + subProfileId` 范围 token。
  - feature off 时带 `subProfileId` 扩展签名返回值与旧签名一致，不引入 `subProfileId` 过滤语义。

### ATM Service / Manager 用例

#### CASE-ATM-SVC-010 ATM JS 新路径通过 `callingUid` 解析 `userId`

- 对应测试点：TC-03
- 建议测试套：ATM Service
- 建议文件：`services/accesstokenmanager/test/unittest/service/accesstoken_manager_service_test.cpp`
- 测试规格：
  - 验证 JS 新路径不传 `userId`，服务端从 `callingUid` 推导当前用户。
- 前置条件：
  - 车机场景，feature 开启。
  - 可构造带确定 `callingUid` 的调用上下文。
- 测试步骤：
  1. 构造一个 `callingUid` 对应 `userIdX` 的请求。
  2. 调用 JS 新路径对应服务端入口。
  3. 检查后续逻辑使用的用户维度。
- 预期结果：
  - 服务端解析出的用户为 `userIdX`。
  - set/get 结果只落在 `userIdX + subProfileId + permissionName` 维度。
  - `userId=0` 维度和其他用户维度没有新增或被修改的 toggle 数据。

#### CASE-ATM-SVC-011 ATM 非法 `subProfileId` 返回不存在错误码

- 对应测试点：TC-05
- 建议测试套：ATM Service
- 建议文件：`services/accesstokenmanager/test/unittest/service/accesstoken_manager_service_test.cpp`
- 测试规格：
  - 验证 `subProfileId` 不属于当前 `userId` 时返回对应不存在错误码。
- 前置条件：
  - 车机场景，feature 开启。
  - 可解析得到当前 `userId`。
  - 构造一个不属于当前 `userId` 的 `subProfileId`。
- 测试步骤：
  1. 调用新路径 set。
  2. 调用新路径 get。
- 预期结果：
  - 两次调用均返回 `ERR_PERMISSION_REQUEST_TOGGLE_SUBPROFILE_NOT_EXIST`。
  - 不产生写入副作用。

#### CASE-ATM-SVC-012 ATM 非 JS 新路径 `userId != 0` 返回 `201`

- 对应测试点：TC-23
- 建议测试套：ATM Service
- 建议文件：`services/accesstokenmanager/test/unittest/service/accesstoken_manager_service_test.cpp`
- 测试规格：
  - 验证非 JS 入口传 `userId != 0` 时直接返回 `201`。
- 前置条件：
  - 车机场景，feature 开启。
- 测试步骤：
  1. 调用新路径 set，传 `userId=1`。
  2. 调用新路径 get，传 `userId=1`。
- 预期结果：
  - 两次调用均返回 `201`。
  - 不进入后续 `subProfileId` 归属校验。

#### CASE-ATM-SVC-013 ATM 历史数据升级后默认 `sub_profile_id=-1`

- 对应测试点：TC-25
- 建议测试套：ATM Manager
- 建议文件：`services/accesstokenmanager/test/unittest/permission/permission_request_toggle_manager_test.cpp`
- 测试规格：
  - 验证旧数据库记录升级后按 `sub_profile_id=-1` 旧路径语义处理。
- 前置条件：
  - 准备升级前旧格式数据。
- 测试步骤：
  1. 执行升级流程。
  2. 查询升级后的旧记录。
  3. 使用新路径查询继承值。
  4. 对新路径执行写入。
- 预期结果：
  - 升级后旧记录被识别为旧路径记录。
  - 旧接口查询返回升级前状态值。
  - 新路径查询合法 `subProfileId` 时返回同一个旧路径状态值。
  - 旧记录清理前，新路径 set 返回 `ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT`。
  - 旧记录清理后，新路径 set/get 成功并返回新写入值。

#### CASE-ATM-SVC-014 ATM 禁止跨 profile 读写

- 对应测试点：TC-29
- 建议测试套：ATM Service
- 建议文件：`services/accesstokenmanager/test/unittest/service/accesstoken_manager_service_test.cpp`
- 测试规格：
  - 验证属于其他 `userId` 的 `subProfileId` 无法被当前用户读写。
- 前置条件：
  - 车机场景，feature 开启。
  - 构造一个属于其他 `userId` 的 `subProfileId`。
- 测试步骤：
  1. 调用新路径 set。
  2. 调用新路径 get。
- 预期结果：
  - 两次调用均失败。
  - 返回 `ERR_PERMISSION_REQUEST_TOGGLE_SUBPROFILE_NOT_EXIST`。
  - 不写入当前用户、目标 profile 所属用户或旧路径维度的数据。

### Privacy Kit 用例

#### CASE-PRI-KIT-015 Privacy 新路径按 `userId + subProfileId` 隔离设置/查询

- 对应测试点：TC-02
- 建议测试套：Privacy Kit
- 建议文件：`interfaces/innerkits/privacy/test/unittest/src/permission_used_toggle_status_test.cpp`
- 测试规格：
  - 验证 feature 开启且 `subProfileId` 合法时，Privacy 新路径按 `userId + subProfileId` 维度独立存取。
- 前置条件：
  - 车机场景，feature 开启。
  - 当前 `userId` 下存在两个合法 `subProfileId`。
- 测试步骤：
  1. 为 `subProfileIdA` 设置 record toggle 为 `true`。
  2. 查询 `subProfileIdA` 结果。
  3. 查询 `subProfileIdB` 结果。
  4. 将 `subProfileIdA` 改为 `false` 并再次查询 A/B。
- 预期结果：
  - `subProfileIdA` 结果随写入变化。
  - `subProfileIdB` 不受影响。

#### CASE-PRI-KIT-016 Privacy 老数据阻塞新路径写入 `true/false`

- 对应测试点：TC-09, TC-10
- 建议测试套：Privacy Kit
- 建议文件：`interfaces/innerkits/privacy/test/unittest/src/permission_used_toggle_status_test.cpp`
- 测试规格：
  - 验证旧 `userId` 维度 record toggle 存在时，新路径对 `true/false` 写入均被阻塞。
- 前置条件：
  - 车机场景，feature 开启。
  - 当前 `userId` 已存在旧路径 record toggle 数据。
- 测试步骤：
  1. 通过旧接口写入 record toggle。
  2. 新路径 set `true`。
  3. 新路径 set `false`。
  4. 新路径 get。
- 预期结果：
  - 步骤 2、3 均返回 `ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT`。
  - 步骤 4 返回旧路径继承值。

#### CASE-PRI-KIT-017 Privacy `subProfileId<0` 走旧路径

- 对应测试点：TC-12
- 建议测试套：Privacy Kit
- 建议文件：`interfaces/innerkits/privacy/test/unittest/src/permission_used_toggle_status_test.cpp`
- 测试规格：
  - 验证负值 `subProfileId` 在 Privacy 中也统一走旧路径。
- 前置条件：
  - 车机场景，feature 开启。
- 测试步骤：
  1. 传 `subProfileId=-1` 调用扩展后的 set 接口写入 `true`。
  2. 使用旧接口查询。
  3. 传 `subProfileId=-2` 查询。
- 预期结果：
  - 新旧接口查询结果一致。
  - 不触发不存在错误码。

#### CASE-PRI-KIT-018 Privacy 新路径查询继承旧路径值

- 对应测试点：TC-14
- 建议测试套：Privacy Kit
- 建议文件：`interfaces/innerkits/privacy/test/unittest/src/permission_used_toggle_status_test.cpp`
- 测试规格：
  - 验证仅存在旧路径记录时，新路径查询返回旧记录值。
- 前置条件：
  - 车机场景，feature 开启。
  - 当前 `userId` 仅存在旧路径 record toggle 数据。
- 测试步骤：
  1. 旧接口写入 `true`。
  2. 新路径查询。
  3. 旧接口改写为 `false`。
  4. 新路径再次查询。
- 预期结果：
  - 两次新路径查询分别返回 `true`、`false`。

#### CASE-PRI-KIT-019 Privacy 旧路径清理后允许切换到新路径

- 对应测试点：TC-16
- 建议测试套：Privacy Kit
- 建议文件：`interfaces/innerkits/privacy/test/unittest/src/permission_used_toggle_status_test.cpp`
- 测试规格：
  - 验证旧路径数据库和缓存清理完成后，新路径可正常写入和查询。
- 前置条件：
  - 车机场景，feature 开启。
  - 当前 `userId` 先存在旧路径数据。
- 测试步骤：
  1. 旧路径写入 record toggle。
  2. 新路径写入，确认先冲突。
  3. 旧路径清理旧数据。
  4. 再次使用新路径写入和查询。
- 预期结果：
  - 清理前返回冲突错误码。
  - 清理后新路径写入成功且查询返回新值。

#### CASE-PRI-KIT-020 Privacy 新数据存在时旧接口写入被阻塞

- 对应测试点：TC-18
- 建议测试套：Privacy Kit
- 建议文件：`interfaces/innerkits/privacy/test/unittest/src/permission_used_toggle_status_test.cpp`
- 测试规格：
  - 验证已进入新路径模式后，旧接口不允许再写入。
- 前置条件：
  - 车机场景，feature 开启。
  - 当前 `userId` 某合法 `subProfileId` 已存在新路径数据。
- 测试步骤：
  1. 新路径先写入一条数据。
  2. 旧接口 set `true`。
  3. 旧接口 set `false`。
  4. 新路径再次查询原状态。
- 预期结果：
  - 步骤 2、3 均返回 `ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT`。
  - 新路径原状态保持不变。

#### CASE-PRI-KIT-021 feature 未定义时 Privacy 新签名返回 `801`

- 对应测试点：TC-20
- 建议测试套：Privacy Kit
- 建议文件：
  - `interfaces/innerkits/privacy/test/unittest/src/permission_used_toggle_status_test.cpp`
  - `frameworks/js/napi/privacy/src/permission_record_manager_napi.cpp`
  - `frameworks/ets/ani/privacy/src/privacy_manager.cpp`
- 测试规格：
  - 验证 `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 未定义时，Privacy 新增 `subProfileId` 签名不可用并返回 `801`。
- 前置条件：
  - `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 未定义。
- 测试步骤：
  1. 以 feature off 构建编译运行 `#else` 分支。
  2. 调用或覆盖 JS/NAPI 新签名 set 执行分支。
  3. 调用或覆盖 JS/NAPI 新签名 get 执行分支。
  4. 调用或覆盖 ETS/ANI 新签名 set/get 执行分支。
- 预期结果：
  - 步骤 2~4 均返回或抛出 `801`。
  - 不写入旧路径 record toggle，也不写入 `subProfileId` 新路径 record toggle。

#### CASE-PRI-KIT-022 feature 未定义时 Privacy 旧 API 保持旧行为

- 对应测试点：TC-22
- 建议测试套：Privacy Kit
- 建议文件：`interfaces/innerkits/privacy/test/unittest/src/permission_used_toggle_status_test.cpp`
- 测试规格：
  - 验证 feature 未定义时旧接口行为不发生语义变化，InnerKit 显式传 `subProfileId>=0` 也按旧路径归一化处理。
- 前置条件：
  - `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 未定义。
  - 当前 `userId` 不存在新路径数据。
- 测试步骤：
  1. 使用带 `subProfileId>=0` 的 InnerKit 扩展签名 set `false`。
  2. 使用旧签名 get。
  3. 使用旧签名 set `true`。
  4. 使用带 `subProfileId>=0` 的 InnerKit 扩展签名 get。
- 预期结果：
  - 步骤 2 返回 `false`，说明 feature off 下带 `subProfileId` 调用被归一化到旧路径。
  - 步骤 4 返回 `true`，说明旧路径写入可被带 `subProfileId` 调用读取。
  - 不返回 `801`、subProfile 不存在或 storage conflict。

### Privacy Service / Record 用例

#### CASE-PRI-SVC-023 Privacy JS 新路径通过 `callingUid` 解析 `userId`

- 对应测试点：TC-04
- 建议测试套：Privacy Service
- 建议文件：`services/privacymanager/test/unittest/service/privacy_manager_service_test.cpp`
- 测试规格：
  - 验证 Privacy JS 新路径不传 `userId` 时，服务端按 `callingUid` 推导当前用户。
- 前置条件：
  - 车机场景，feature 开启。
  - 可构造带确定 `callingUid` 的调用上下文。
- 测试步骤：
  1. 构造 `callingUid` 对应 `userIdX` 的请求。
  2. 调用 JS 新路径对应服务入口。
  3. 观察服务端使用的用户维度。
- 预期结果：
  - 服务端解析出的用户为 `userIdX`。
  - set/get 结果只落在 `userIdX + subProfileId` 维度。
  - `userId=0` 维度和其他用户维度没有新增或被修改的 record toggle 数据。

#### CASE-PRI-SVC-024 Privacy 非法 `subProfileId` 返回不存在错误码

- 对应测试点：TC-06
- 建议测试套：Privacy Service
- 建议文件：`services/privacymanager/test/unittest/service/privacy_manager_service_test.cpp`
- 测试规格：
  - 验证 `subProfileId` 不属于当前 `userId` 时返回对应不存在错误码。
- 前置条件：
  - 车机场景，feature 开启。
  - 可解析得到当前 `userId`。
  - 构造一个不属于当前 `userId` 的 `subProfileId`。
- 测试步骤：
  1. 调用新路径 set。
  2. 调用新路径 get。
- 预期结果：
  - 两次调用均返回 `ERR_PERMISSION_USED_RECORD_SUBPROFILE_NOT_EXIST`。
  - 不产生状态写入。

#### CASE-PRI-SVC-025 Privacy 非 JS 新路径 `userId != 0` 返回 `201`

- 对应测试点：TC-24
- 建议测试套：Privacy Service
- 建议文件：`services/privacymanager/test/unittest/service/privacy_manager_service_test.cpp`
- 测试规格：
  - 验证非 JS 入口传 `userId != 0` 时直接返回 `201`。
- 前置条件：
  - 车机场景，feature 开启。
- 测试步骤：
  1. 调用新路径 set，传 `userId=1`。
  2. 调用新路径 get，传 `userId=1`。
- 预期结果：
  - 两次调用均返回 `201`。
  - 不进入后续归属校验和存储逻辑。

#### CASE-PRI-SVC-026 Privacy 历史数据升级后默认 `sub_profile_id=-1`

- 对应测试点：TC-26
- 建议测试套：Privacy Record
- 建议文件：`services/privacymanager/test/unittest/record/permission_record_manager_test.cpp`
- 测试规格：
  - 验证 Privacy 旧数据库记录升级后按 `sub_profile_id=-1` 旧路径语义处理。
- 前置条件：
  - 准备升级前旧格式数据。
- 测试步骤：
  1. 执行升级流程。
  2. 查询升级后的记录。
  3. 使用新路径查询继承值。
  4. 对新路径执行写入验证冲突。
- 预期结果：
  - 升级后旧记录被识别为旧路径记录。
  - 旧接口查询返回升级前状态值。
  - 新路径查询合法 `subProfileId` 时返回同一个旧路径状态值。
  - 旧记录清理前，新路径 set 返回 `ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT`。
  - 旧记录清理后，新路径 set/get 成功并返回新写入值。

#### CASE-PRI-SVC-027 Privacy 禁止跨 profile 读写

- 对应测试点：TC-30
- 建议测试套：Privacy Service
- 建议文件：`services/privacymanager/test/unittest/service/privacy_manager_service_test.cpp`
- 测试规格：
  - 验证属于其他 `userId` 的 `subProfileId` 无法被当前用户读写。
- 前置条件：
  - 车机场景，feature 开启。
  - 构造一个属于其他 `userId` 的 `subProfileId`。
- 测试步骤：
  1. 调用新路径 set。
  2. 调用新路径 get。
- 预期结果：
  - 两次调用均失败。
  - 返回 `ERR_PERMISSION_USED_RECORD_SUBPROFILE_NOT_EXIST`。
  - 不写入当前用户、目标 profile 所属用户或旧路径维度的数据。

#### CASE-PRI-SVC-028 Privacy remote record 按 `userId + subProfileId` 隔离

- 对应测试点：TC-35
- 建议测试套：Privacy Record
- 建议文件：`services/privacymanager/test/unittest/record/privacy_toggle_record_test.cpp`
- 测试规格：
  - 验证 remote record 不会在不同 `subProfileId` 间串写、串查、串删。
- 前置条件：
  - 车机场景，feature 开启。
  - 当前 `userId` 下存在两个合法 `subProfileId`。
- 测试步骤：
  1. 为 `subProfileIdA` 和 `subProfileIdB` 分别写入 remote record。
  2. 分别查询 A/B 的 remote record。
  3. 删除 `subProfileIdA` 的 remote record。
  4. 再次查询 A/B。
- 预期结果：
  - 查询 `subProfileIdA` 只返回 A 的 remote record，查询 `subProfileIdB` 只返回 B 的 remote record。
  - 删除 `subProfileIdA` 后，A 查询为空或不包含已删除记录，B 查询仍返回 B 的原记录。
  - 统计、合并或清理过程中不把 A/B 的 remote record 合并到同一个 `userId` 维度结果中。

## 多设备与错误码回归用例

### CASE-FEATURE-OFF-029 feature 未定义产品新签名不可用

- 对应测试点：TC-31, TC-32
- 建议测试套：多设备回归 / ATM Kit / Privacy Kit
- 建议文件：
  - `interfaces/innerkits/accesstoken/test/unittest/HapAttributeTest/permission_request_toggle_status_test.cpp`
  - `interfaces/innerkits/privacy/test/unittest/src/permission_used_toggle_status_test.cpp`
- 测试规格：
  - 验证任意未定义 `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 的产品，ATM/Privacy 同名新增 `subProfileId` 签名不可用，旧 API 保持原行为。
- 前置条件：
  - 以 `access_token_support_subprofile=false` 或无 `os_account` 依赖的构建方式生成 feature off 测试二进制。
  - 未定义 `ACCESS_TOKEN_SUPPORT_SUBPROFILE`。
  - 调用方具备旧接口原有权限，避免权限不足掩盖 `801`。
- 测试步骤：
  1. 执行 ATM feature off `#else` 用例，覆盖新增签名 `801` 映射和旧路径归一化。
  2. 执行 Privacy feature off `#else` 用例，覆盖新增签名 `801` 映射和旧路径归一化。
  3. 执行 `GetTokenIDByUserID` feature off `#else` 用例，比较旧签名和带 `subProfileId` 签名的返回集合。
- 预期结果：
  - ATM 新签名返回 `801`，旧路径 set/get 成功。
  - Privacy 新签名返回 `801`，旧路径 set/get 成功。
  - `GetTokenIDByUserID(userId, tokenIdList, subProfileId)` 与旧签名结果一致。
  - 不写入 `subProfileId` 维度数据，不产生 storage conflict 或 subProfile 不存在错误。
- 恢复要求：
  - 恢复 caller token 和 uid。
  - 若测试前写入旧路径开关状态，测试后恢复原状态。

### CASE-VEHICLE-ATM-031 车机端 ATM 新签名行为闭环

- 对应测试点：TC-33
- 建议测试套：ATM Kit + ATM Service / Manager
- 建议文件：
  - `interfaces/innerkits/accesstoken/test/unittest/HapAttributeTest/permission_request_toggle_status_test.cpp`
  - `services/accesstokenmanager/test/unittest/service/accesstoken_manager_service_test.cpp`
  - `services/accesstokenmanager/test/unittest/permission/permission_request_toggle_manager_test.cpp`
- 测试规格：
  - 验证车机端 ATM 新签名可用，并受合法 `subProfileId`、旧数据阻塞、新数据阻塞、负值旧路径、`userId!=0` 和错误码规则约束。
- 前置条件：
  - 车机产品编译配置。
  - `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 开启。
  - 当前 `userId` 下存在两个合法 `subProfileId`。
  - 调用方具备 `DISABLE_PERMISSION_DIALOG` 和 `GET_SENSITIVE_PERMISSIONS`。
- 测试步骤：
  1. 对 `subProfileIdA` 设置 permission toggle 为 `CLOSED` 并查询。
  2. 查询 `subProfileIdB` 的同一 permission toggle。
  3. 通过旧路径写入旧数据后，对 `subProfileIdA` 分别 set `OPEN` 和 `CLOSED`。
  4. 旧路径清理完成后，再对 `subProfileIdA` 设置并查询。
  5. 已存在新路径数据后，调用旧接口 set。
  6. 传 `subProfileId<0` 调用 set/get。
  7. 通过 service 入口传 `userId!=0` 调用 set/get。
- 预期结果：
  - 步骤 1/2 证明 `userId + subProfileId + permissionName` 维度隔离。
  - 步骤 3 返回 `ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT`。
  - 步骤 4 写入成功且查询返回新值。
  - 步骤 5 返回 `ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT`。
  - 步骤 6 按旧路径处理，不触发 subProfile 校验。
  - 步骤 7 返回 `201`。
- 恢复要求：
  - 恢复 caller token、uid。
  - 清理本用例写入的旧路径和新路径 toggle 数据，或恢复到进入用例前状态。

### CASE-VEHICLE-PRI-032 车机端 Privacy 新签名行为闭环

- 对应测试点：TC-34
- 建议测试套：Privacy Kit + Privacy Service / Record
- 建议文件：
  - `interfaces/innerkits/privacy/test/unittest/src/permission_used_toggle_status_test.cpp`
  - `services/privacymanager/test/unittest/service/privacy_manager_service_test.cpp`
  - `services/privacymanager/test/unittest/record/privacy_toggle_record_test.cpp`
- 测试规格：
  - 验证车机端 Privacy 新签名可用，并受合法 `subProfileId`、旧数据阻塞、新数据阻塞、负值旧路径、`userId!=0` 和错误码规则约束。
- 前置条件：
  - 车机产品编译配置。
  - `ACCESS_TOKEN_SUPPORT_SUBPROFILE` 开启。
  - 当前 `userId` 下存在两个合法 `subProfileId`。
  - 调用方具备 `PERMISSION_RECORD_TOGGLE` 和 `PERMISSION_USED_STATS`。
- 测试步骤：
  1. 对 `subProfileIdA` 设置 record toggle 为 `false` 并查询。
  2. 查询 `subProfileIdB` 的 record toggle。
  3. 通过旧路径写入旧数据后，对 `subProfileIdA` 分别 set `true` 和 `false`。
  4. 旧路径清理完成后，再对 `subProfileIdA` 设置并查询。
  5. 已存在新路径数据后，调用旧接口 set。
  6. 传 `subProfileId<0` 调用 set/get。
  7. 通过 service 入口传 `userId!=0` 调用 set/get。
- 预期结果：
  - 步骤 1/2 证明 `userId + subProfileId` 维度隔离。
  - 步骤 3 返回 `ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT`。
  - 步骤 4 写入成功且查询返回新值。
  - 步骤 5 返回 `ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT`。
  - 步骤 6 按旧路径处理，不触发 subProfile 校验。
  - 步骤 7 返回 `201`。
- 恢复要求：
  - 恢复 caller token、uid。
  - 清理本用例写入的旧路径和新路径 record toggle 数据，或恢复到进入用例前状态。

### CASE-ERROR-033 JS/ANI/native 错误码可区分

- 对应测试点：TC-36
- 建议测试套：多设备/错误码回归套
- 建议文件：
  - `interfaces/innerkits/accesstoken/test/unittest/PermDenyTest/accesstoken_deny_test.cpp`
  - `interfaces/innerkits/privacy/test/unittest/src/permission_deny_test.cpp`
  - `services/accesstokenmanager/test/unittest/service/accesstoken_manager_service_test.cpp`
  - `services/privacymanager/test/unittest/service/privacy_manager_service_test.cpp`
  - JS/ANI 对应 API 测试文件
- 测试规格：
  - 验证 `801`、`201`、subProfile 不存在、storage conflict 在 JS/ANI/native 层可区分，不被统一映射成同一个失败码。
- 前置条件：
  - 准备 feature off、feature on、非法 `userId`、非法 `subProfileId`、老数据冲突和新数据冲突场景。
- 测试步骤：
  1. feature off 调用新增 `subProfileId` 签名。
  2. service 入口传 `userId!=0`。
  3. 传入不属于当前 `userId` 的 `subProfileId`。
  4. 旧路径数据存在时调用新路径 set。
  5. 新路径数据存在时调用旧接口 set。
  6. 分别在 JS、ANI、native 层读取返回码或异常码。
- 预期结果：
  - 步骤 1 返回 `801`。
  - 步骤 2 返回 `201`。
  - 步骤 3 ATM 返回 `ERR_PERMISSION_REQUEST_TOGGLE_SUBPROFILE_NOT_EXIST`，Privacy 返回 `ERR_PERMISSION_USED_RECORD_SUBPROFILE_NOT_EXIST`。
  - 步骤 4/5 ATM 返回 `ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT`，Privacy 返回 `ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT`。
  - JS/ANI/native 对同一底层场景的错误码映射与 spec 约定一致。
- 恢复要求：
  - 恢复 caller token、uid、feature/构建环境。
  - 清理或恢复测试写入的旧路径和新路径 toggle 数据。

## 规格追溯表

| spec 规格项 | 对应测试点 | 对应用例 |
|---|---|---|
| AC-1.1 / BR-1 / FR-1 | TC-01, TC-33 | CASE-ATM-KIT-001, CASE-VEHICLE-ATM-031 |
| AC-1.2 / BR-2 / VM-1 | TC-03 | CASE-ATM-SVC-010 |
| AC-1.3 / BR-3 / EX-2 / VM-2 / 安全 NFR | TC-05, TC-29 | CASE-ATM-SVC-011, CASE-ATM-SVC-014 |
| AC-1.4 / BR-4 / EX-3 / VM-3 | TC-07, TC-08 | CASE-ATM-KIT-002 |
| AC-1.5 / BR-6 / FR-6 / VM-5 | TC-11 | CASE-ATM-KIT-003 |
| AC-2.1 / BR-1 / FR-2 | TC-02, TC-34 | CASE-PRI-KIT-015, CASE-VEHICLE-PRI-032 |
| AC-2.2 / BR-2 / VM-1 | TC-04 | CASE-PRI-SVC-023 |
| AC-2.3 / BR-3 / EX-2 / VM-2 / 安全 NFR | TC-06, TC-30 | CASE-PRI-SVC-024, CASE-PRI-SVC-027 |
| AC-2.4 / BR-4 / EX-3 / VM-3 | TC-09, TC-10 | CASE-PRI-KIT-016 |
| AC-2.5 / BR-6 / FR-6 / VM-5 | TC-12 | CASE-PRI-KIT-017 |
| AC-3.1 / BR-4 / BR-7 / BR-8 / FR-3 / FR-7 | TC-13, TC-14, TC-25, TC-26, TC-37, TC-38 | CASE-ATM-KIT-004, CASE-PRI-KIT-018, CASE-ATM-SVC-013, CASE-PRI-SVC-026, CASE-OTA-ATM-001, CASE-OTA-PRI-002 |
| AC-3.2 / BR-7 / BR-8 / FR-4 / RC-1 / VM-6 | TC-15, TC-16, TC-37, TC-38 | CASE-ATM-KIT-005, CASE-PRI-KIT-019, CASE-OTA-ATM-001, CASE-OTA-PRI-002 |
| AC-3.3 / BR-5 / FR-5 / EX-4 / VM-4 | TC-17, TC-18 | CASE-ATM-KIT-006, CASE-PRI-KIT-020 |
| AC-3.4 / BR-1 / BR-9 / EX-0 / VM-7 / 多设备适配 | TC-19, TC-20, TC-31, TC-32 | CASE-ATM-KIT-007, CASE-PRI-KIT-021, CASE-FEATURE-OFF-029 |
| AC-3.5 / BR-1 / BR-9 / VM-8 / 生态兼容 | TC-21, TC-22, TC-28 | CASE-ATM-KIT-008, CASE-PRI-KIT-022, CASE-ATM-KIT-009 |
| `AccessTokenKit::GetTokenIDByUserID(..., subProfileId)` API 变更 | TC-27, TC-28 | CASE-ATM-KIT-009 |
| Privacy remote record subProfile 隔离 | TC-35 | CASE-PRI-SVC-028 |
| 问题定位 NFR / 错误码映射 | TC-36 | CASE-ERROR-033 |

## OTA 手工用例

### CASE-OTA-ATM-001 ATM OTA 升级后旧数据兼容与切换

- 对应测试点：TC-37
- 建议测试类型：手工
- 测试规格：
  - 验证 OTA 升级前已存在的 ATM 旧路径 toggle 数据，在升级后仍按 `sub_profile_id=-1` 旧语义生效，并支持后续切换到新路径。
- 前置条件：
  - 升级前版本不支持 `subProfileId`。
  - 设备上已通过旧接口写入 ATM toggle 数据。
  - 升级包包含本次需求的数据库结构和业务逻辑变更。
- 测试步骤：
  1. 在升级前版本通过旧接口写入 ATM toggle 数据。
  2. 执行 OTA 升级到目标版本。
  3. 升级后先通过旧接口查询原 toggle 状态。
  4. 升级后使用新路径对合法 `subProfileId` 查询同一权限状态。
  5. 升级后直接通过新路径写入，观察是否被旧数据阻塞。
  6. 通过旧路径清理数据库和缓存中的旧数据。
  7. 再通过新路径对合法 `subProfileId` 设置和查询。
- 预期结果：
  - 升级后旧接口仍能读到升级前写入的状态。
  - 新路径查询先继承旧路径值。
  - 旧数据清理前，新路径写入被阻塞。
  - 清理后，新路径设置与查询恢复正常。

### CASE-OTA-PRI-002 Privacy OTA 升级后旧数据兼容与切换

- 对应测试点：TC-38
- 建议测试类型：手工
- 测试规格：
  - 验证 OTA 升级前已存在的 Privacy 旧路径 record toggle 数据，在升级后仍按 `sub_profile_id=-1` 旧语义生效，并支持后续切换到新路径。
- 前置条件：
  - 升级前版本不支持 `subProfileId`。
  - 设备上已通过旧接口写入 Privacy record toggle 数据。
  - 升级包包含本次需求的数据库结构和业务逻辑变更。
- 测试步骤：
  1. 在升级前版本通过旧接口写入 Privacy record toggle 数据。
  2. 执行 OTA 升级到目标版本。
  3. 升级后先通过旧接口查询原 toggle 状态。
  4. 升级后使用新路径对合法 `subProfileId` 查询 record toggle。
  5. 升级后直接通过新路径写入，观察是否被旧数据阻塞。
  6. 通过旧路径清理数据库和缓存中的旧数据。
  7. 再通过新路径对合法 `subProfileId` 设置和查询。
- 预期结果：
  - 升级后旧接口仍能读到升级前写入的状态。
  - 新路径查询先继承旧路径值。
  - 旧数据清理前，新路径写入被阻塞。
  - 清理后，新路径设置与查询恢复正常。

## 实现优先级

- P0 先实现：
  - ATM/Privacy 正常路径隔离
  - `801`
  - `201`
  - `subProfileId<0`
  - 老数据阻塞新写
  - 新数据阻塞旧写
  - 旧路径继承
  - 升级默认 `-1`
- P1 再实现：
  - `callingUid -> userId`
  - `GetTokenIDByUserID(..., subProfileId)`
  - remote record 隔离
  - 多设备补充回归

# Gate: Define

## Stage

- 阶段: Define
- 变更ID: permission-toggle-management-based-subprofileid
- 日期: 2026-06-11
- 结论: Approved

## Profile 判定

- [x] 已扫描 `ohos-sdd/profiles/` 目录，确认可用 Profile 列表
- [x] 已根据仓路径或需求内容判定是否命中 Profile
- [ ] 若命中且有子 Profile，已进一步判定子 Profile
- [x] Profile 追加规则已合并到后续阶段的检查项和 Gate 条件

证据：
- 仓路径 `base/security/access_token` 未命中当前内置 `arkweb/arkui/arkgraphic/arkdata` profile，按 `none` 处理。

## 定义阶段检查

### 入口检查

- [x] 原始问题和期望结果已记录
- [x] 需求来源和责任人已明确
- [x] 待澄清问题已逐项关闭，状态均为已澄清或明确 N/A
- [x] 讨论记录包含需求方/Owner/SIG 的明确确认证据
- [x] 澄清结论全部适用项已勾选
- [x] 功能范围（包含/不包含）已确认
- [x] API 变更已评估（如有）
- [x] 兼容性和非功能需求已确认
- [x] 依赖和风险已识别并有缓解方案

理由：
- 已从用户输入和源码检索整理出影响面。
- 已获得 Q-1 ~ Q-4 的需求方确认。
- 已获得 Q-5 的需求方确认，并锁定“仅车机 + feature 隔离 + 其他平台保持原行为”。
- 已获得旧 JS API 兼容行为确认：旧 API 保持原行为，新增 API 使用 `subProfileId`。
- 已获得旧数据兼容规则确认：旧 `userId` 数据存在时，按 `subProfileId` 执行 `status=true` 或 `status=false` 都返回错误码；必须通过旧 `userId` 路径清理数据库和缓存中的老数据后，才允许按 `subProfileId` 新写入。
- 已获得新增路径校验规则确认：`userId=0` 时解析 `callingUid`；`userId!=0` 时返回 `201`；`subProfileId>=0` 时必须校验当前 `userId` 下是否存在对应 `subProfileId`，不存在则返回新增错误码。
- 已确认目标版本为 `master`，Owner 暂记 `TBD`。
- 需求方已明确回复“批准 Define，进入 Stage 2”。

### 出口检查

- [x] 所有 P0/P1 用户故事有 AC（WHEN/THEN 格式）
- [x] 每条 AC 可测试、可度量
- [x] `manifest.target_release` 已确认或明确 master
- [x] `manifest.profile` 已确认或明确 none
- [x] 不涉及项已显式标记 N/A
- [x] `manifest.target_release` 已确认或明确 master
- [x] 需求方已批准当前基线，审批证据记录于本 gate
- [x] `gates/define.md` 总结论为 `通过/Approved`

理由：
- 当前只完成草案，未获得需求方/Owner 审批证据。

## 总结

- 当前状态: Approved
- 审批证据:
  - 2026-06-11，需求方明确回复：`批准 Define，进入 Stage 2`

- 下一步:
  - 创建 `design.md` 和 `spec.md`
  - 完成 Stage 2 gate 检查后，请需求方审阅并批准进入 Stage 3

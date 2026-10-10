/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "access_token_error.h"
#include "add_spm_data_task.h"
#include "fake_token_setproc.h"
#include "generic_values.h"
#include "kernel_and_db_lock.h"
#include "kernel_and_db_transaction.h"
#include "mock_access_token_db_operator.h"
#include "permission_data_brief.h"
#include "remove_spm_data_task.h"
#include "spm_data_kernel_common.h"
#include "token_field_const.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr uint32_t MAX_UID_RANGE = 200000;

HapTokenInfo BuildHapInfo(AccessTokenID tokenId, const std::string& bundleName)
{
    HapTokenInfo hapInfo = {};
    hapInfo.ver = 1;
    hapInfo.userID = 100;  // 100: userId
    hapInfo.bundleName = bundleName;
    hapInfo.apiVersion = 12; // 12: api version
    hapInfo.instIndex = 0;
    hapInfo.dlpType = DLP_COMMON;
    hapInfo.tokenID = tokenId;
    hapInfo.tokenAttr = 0;
    hapInfo.uid = 20100000 + (tokenId % MAX_UID_RANGE); // 20100000: base uid
    return hapInfo;
}

BundleNoCachedInfo BuildNoCached()
{
    BundleNoCachedInfo info;
    info.apl = APL_NORMAL;
    info.distributionType = static_cast<int32_t>(Security::Verify::AppDistType::NONE_TYPE);
    info.idType = 2;  // 2: idType
    info.ownerid = 1;
    return info;
}

std::vector<BriefPermData> BuildBriefList(uint16_t permCode)
{
    BriefPermData data = {0};
    data.permCode = permCode;
    data.status = PERMISSION_GRANTED;
    data.flag = PERMISSION_SYSTEM_FIXED;
    return { data };
}

// noCached and extendPerms must be caller-owned and outlive the Stage* call:
// SpmDataParam holds reference_wrapper, so referencing locals of this helper
// would leave the returned params dangling (UB) after the helper returns.
std::vector<SpmDataParam> BuildAddParams(const HapTokenInfo& hapInfo,
    const std::vector<BriefPermData>& brief, const BundleNoCachedInfo& noCached,
    const std::vector<PermissionWithValue>& extendPerms)
{
    return { SpmDataParam{hapInfo, noCached, brief, extendPerms, nullptr, true} };
}

DelInfo BuildDelInfo(AccessTokenID tokenId)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO;
    delInfo.delValue = condition;
    return delInfo;
}
}

class KernelAndDBTransactionTest : public testing::Test {
public:
    void SetUp() override
    {
        ResetFakeSpmKernelState();
        ResetMockDbState();
    }

    void TearDown() override
    {
        ResetFakeSpmKernelState();
        ResetMockDbState();
    }
};

/**
 * @tc.name: RemoveSpmDataTask001
 * @tc.desc: Verify batch remove reports success and removes both spm entries and permission data.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTask001, TestSize.Level0)
{
    std::vector<RemoveSpmDataParam> params = { { 0x301, nullptr }, { 0x302, nullptr } };

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    ASSERT_EQ(RET_SUCCESS, task.Remove(errIndex));
    EXPECT_EQ(2u, errIndex); // no failure: errIndex stays at the item count
    EXPECT_EQ(2, GetFakeSpmKernelState().getCallCount);      // entry capture per token
    EXPECT_EQ(0, GetFakeSpmKernelState().getPermsCallCount); // old perms come from the caller
    EXPECT_EQ(2, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(2, GetFakeSpmKernelState().removePermCallCount);
    EXPECT_EQ(2u, GetFakeSpmKernelState().removedTokenIds.size());
}

/**
 * @tc.name: RemoveSpmDataTask002
 * @tc.desc: Verify empty params returns ERR_PARAM_INVALID.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTask002, TestSize.Level0)
{
    RemoveSpmDataTask task({});
    uint32_t errIndex = 99;
    EXPECT_EQ(ERR_PARAM_INVALID, task.Remove(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(0, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(0, GetFakeSpmKernelState().removePermCallCount);
}

/**
 * @tc.name: RemoveSpmDataTask003
 * @tc.desc: Verify oversized params returns ERR_PARAM_INVALID.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTask003, TestSize.Level0)
{
    std::vector<RemoveSpmDataParam> params(256, RemoveSpmDataParam{ 0x303, nullptr }); // 256: exceed MAX_ENTRY_NUM
    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(ERR_PARAM_INVALID, task.Remove(errIndex));
    EXPECT_EQ(0, GetFakeSpmKernelState().removeCallCount);
}

/**
 * @tc.name: RemoveSpmDataTask004
 * @tc.desc: Verify best-effort remove keeps going on single failures and reports the first index.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTask004, TestSize.Level0)
{
    std::vector<RemoveSpmDataParam> params = { { 0x304, nullptr }, { 0x305, nullptr } };
    GetFakeSpmKernelState().removeRet = RET_FAILED;

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Remove(errIndex));
    EXPECT_EQ(0u, errIndex); // first failure index
    // entry removal retries once per token: 2 tokens x 2 calls
    EXPECT_EQ(4, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(2, GetFakeSpmKernelState().removePermCallCount); // both attempted
}

/**
 * @tc.name: RemoveSpmDataTaskRollback001
 * @tc.desc: Verify rollback batch-restores captured spm entries and caller-provided perms (F5.4 fix).
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTaskRollback001, TestSize.Level0)
{
    std::vector<BriefPermData> oldBrief = BuildBriefList(5); // 5: granted opcode
    oldBrief.emplace_back(BuildBriefList(9)[0]);              // 9: granted opcode
    std::vector<RemoveSpmDataParam> params = { { 0x306, &oldBrief }, { 0x307, &oldBrief } };

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    ASSERT_EQ(RET_SUCCESS, task.Remove(errIndex));
    // capture: entry load per token; old perms come from the caller
    EXPECT_EQ(2, GetFakeSpmKernelState().getCallCount);
    EXPECT_EQ(0, GetFakeSpmKernelState().getPermsCallCount);
    EXPECT_EQ(2, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(2, GetFakeSpmKernelState().removePermCallCount);

    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    // entries restored in reverse order with a single batch add
    EXPECT_EQ(1, GetFakeSpmKernelState().addCallCount);
    ASSERT_EQ(1u, GetFakeSpmKernelState().addTokenBatches.size());
    ASSERT_EQ(2u, GetFakeSpmKernelState().addTokenBatches[0].size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x307), GetFakeSpmKernelState().addTokenBatches[0][0]);
    EXPECT_EQ(static_cast<AccessTokenID>(0x306), GetFakeSpmKernelState().addTokenBatches[0][1]);
    // permission bitmaps restored with the opcodes converted from the brief list
    EXPECT_EQ(2, GetFakeSpmKernelState().addPermCallCount);
    ASSERT_EQ(2u, GetFakeSpmKernelState().addPermOpCodeBatches.size());
    EXPECT_EQ(5u, GetFakeSpmKernelState().addPermOpCodeBatches[0][0]);
    EXPECT_EQ(9u, GetFakeSpmKernelState().addPermOpCodeBatches[0][1]);
}

/**
 * @tc.name: RemoveSpmDataTaskRollback002
 * @tc.desc: Verify ENODATA entry skips entry restore while caller-provided perms are still restored.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTaskRollback002, TestSize.Level0)
{
    std::vector<BriefPermData> oldBrief = BuildBriefList(7); // 7: granted opcode
    std::vector<RemoveSpmDataParam> params = { { 0x308, &oldBrief } };
    GetFakeSpmKernelState().getRetSequence = { ENODATA };

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    ASSERT_EQ(RET_SUCCESS, task.Remove(errIndex));
    EXPECT_EQ(1, GetFakeSpmKernelState().getCallCount);
    EXPECT_EQ(0, GetFakeSpmKernelState().getPermsCallCount); // perms are caller-provided
    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    EXPECT_EQ(0, GetFakeSpmKernelState().addCallCount);     // no entry to restore
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount); // perms restored
    ASSERT_EQ(1u, GetFakeSpmKernelState().addPermOpCodeBatches.size());
    EXPECT_EQ(7u, GetFakeSpmKernelState().addPermOpCodeBatches[0][0]);
}

/**
 * @tc.name: RemoveSpmDataTaskRollback003
 * @tc.desc: Verify batch restore skips EEXIST entries and stays idempotent.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTaskRollback003, TestSize.Level0)
{
    std::vector<RemoveSpmDataParam> params = { { 0x309, nullptr }, { 0x30A, nullptr } };
    // first batch add conflicts at index 0, the retry restores the rest
    GetFakeSpmKernelState().addRetSequence = { EEXIST, RET_SUCCESS };

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    ASSERT_EQ(RET_SUCCESS, task.Remove(errIndex));
    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    // batch [0x30A, 0x309] conflicts on 0x30A, retry batch restores [0x309]
    EXPECT_EQ(2, GetFakeSpmKernelState().addCallCount);
    ASSERT_EQ(2u, GetFakeSpmKernelState().addTokenBatches.size());
    ASSERT_EQ(2u, GetFakeSpmKernelState().addTokenBatches[0].size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x30A), GetFakeSpmKernelState().addTokenBatches[0][0]);
    ASSERT_EQ(1u, GetFakeSpmKernelState().addTokenBatches[1].size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x309), GetFakeSpmKernelState().addTokenBatches[1][0]);
    // second rollback is an idempotent success
    EXPECT_EQ(RET_SUCCESS, task.Rollback());
}

/**
 * @tc.name: RemoveSpmDataTaskRollback004
 * @tc.desc: Verify entry capture failure still restores the caller-provided perms.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTaskRollback004, TestSize.Level0)
{
    std::vector<BriefPermData> oldBrief = BuildBriefList(5); // 5: granted opcode
    std::vector<RemoveSpmDataParam> params = { { 0x311, &oldBrief } };
    GetFakeSpmKernelState().getRetSequence = { RET_FAILED };

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    ASSERT_EQ(RET_SUCCESS, task.Remove(errIndex));
    EXPECT_EQ(1, GetFakeSpmKernelState().getCallCount);     // entry load attempted
    EXPECT_EQ(0, GetFakeSpmKernelState().getPermsCallCount); // perms are caller-provided
    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    EXPECT_EQ(0, GetFakeSpmKernelState().addCallCount);     // entry not compensable
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount); // perms restored
    ASSERT_EQ(1u, GetFakeSpmKernelState().addPermOpCodeBatches.size());
    EXPECT_EQ(5u, GetFakeSpmKernelState().addPermOpCodeBatches[0][0]);
}

/**
 * @tc.name: RemoveSpmDataTaskRollback005
 * @tc.desc: Verify caller-provided nullptr oldPermCodes skips perm restore while the entry is restored.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTaskRollback005, TestSize.Level0)
{
    std::vector<RemoveSpmDataParam> params = { { 0x312, nullptr } };

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    ASSERT_EQ(RET_SUCCESS, task.Remove(errIndex));
    EXPECT_EQ(1, GetFakeSpmKernelState().getCallCount);     // entry captured (default get success)
    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    EXPECT_EQ(1, GetFakeSpmKernelState().addCallCount);     // entry restored (single batch)
    EXPECT_EQ(0, GetFakeSpmKernelState().addPermCallCount); // no old perms to restore
}

/**
 * @tc.name: RemoveSpmDataTaskRollback006
 * @tc.desc: Verify a failed spm entry removal is not compensated while perms still are.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTaskRollback006, TestSize.Level0)
{
    std::vector<BriefPermData> oldBrief = BuildBriefList(4); // 4: granted opcode
    std::vector<RemoveSpmDataParam> params = { { 0x315, &oldBrief } };
    GetFakeSpmKernelState().removeRet = RET_FAILED;

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    ASSERT_EQ(RET_SUCCESS, task.Remove(errIndex)); // best-effort: entry removal failed
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(2, GetFakeSpmKernelState().removeCallCount);  // initial + retry
    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    EXPECT_EQ(0, GetFakeSpmKernelState().addCallCount);     // entry still in kernel: not compensated
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount); // perms removed: restored
    ASSERT_EQ(1u, GetFakeSpmKernelState().addPermOpCodeBatches.size());
    EXPECT_EQ(4u, GetFakeSpmKernelState().addPermOpCodeBatches[0][0]);
}

/**
 * @tc.name: RemoveSpmDataTaskRollback007
 * @tc.desc: Verify a failed perm removal is not compensated while the entry still is.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTaskRollback007, TestSize.Level0)
{
    std::vector<BriefPermData> oldBrief = BuildBriefList(6); // 6: granted opcode
    std::vector<RemoveSpmDataParam> params = { { 0x316, &oldBrief } };
    GetFakeSpmKernelState().removePermRet = RET_FAILED;

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    ASSERT_EQ(RET_SUCCESS, task.Remove(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    EXPECT_EQ(1, GetFakeSpmKernelState().addCallCount);     // entry removed: restored (single batch)
    EXPECT_EQ(0, GetFakeSpmKernelState().addPermCallCount); // perms still in kernel: not compensated
}

/**
 * @tc.name: RemoveSpmDataTaskRollback008
 * @tc.desc: Verify denied entries of the caller brief list are filtered out of the restore.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTaskRollback008, TestSize.Level0)
{
    std::vector<BriefPermData> oldBrief = BuildBriefList(5); // 5: granted opcode
    BriefPermData denied = {0};
    denied.permCode = 8; // 8: denied opcode, must not be restored
    denied.status = PERMISSION_DENIED;
    oldBrief.emplace_back(denied);
    std::vector<RemoveSpmDataParam> params = { { 0x317, &oldBrief } };

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    ASSERT_EQ(RET_SUCCESS, task.Remove(errIndex));
    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount);
    ASSERT_EQ(1u, GetFakeSpmKernelState().addPermOpCodeBatches.size());
    ASSERT_EQ(1u, GetFakeSpmKernelState().addPermOpCodeBatches[0].size());
    EXPECT_EQ(5u, GetFakeSpmKernelState().addPermOpCodeBatches[0][0]);
}

/**
 * @tc.name: RemoveSpmDataTaskRollback009
 * @tc.desc: Verify a failed batch entry restore is evented and fails the rollback.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTaskRollback009, TestSize.Level0)
{
    std::vector<BriefPermData> oldBrief = BuildBriefList(2); // 2: granted opcode
    std::vector<RemoveSpmDataParam> params = { { 0x318, &oldBrief } };
    GetFakeSpmKernelState().addRet = RET_FAILED;

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    ASSERT_EQ(RET_SUCCESS, task.Remove(errIndex));
    // batch entry restore failed even after the wrapper retry
    EXPECT_EQ(ERR_KERNEL_COMMON_FAILED, task.Rollback());
    EXPECT_EQ(2, GetFakeSpmKernelState().addCallCount);     // initial + retry
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount); // phase 2 still ran
}

/**
 * @tc.name: RemoveSpmDataTaskRollback010
 * @tc.desc: Verify a failed perm restore is evented and fails the rollback.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTaskRollback010, TestSize.Level0)
{
    std::vector<BriefPermData> oldBrief = BuildBriefList(9); // 9: granted opcode
    std::vector<RemoveSpmDataParam> params = { { 0x319, &oldBrief } };
    GetFakeSpmKernelState().addPermRet = RET_FAILED;

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    ASSERT_EQ(RET_SUCCESS, task.Remove(errIndex));
    // perm restore failed even after the inner retry
    EXPECT_EQ(RET_FAILED, task.Rollback());
    EXPECT_EQ(1, GetFakeSpmKernelState().addCallCount);    // entry restored (single batch)
    EXPECT_EQ(2, GetFakeSpmKernelState().addPermCallCount); // initial + retry
}

/**
 * @tc.name: RemoveSpmDataTaskRollback011
 * @tc.desc: Verify the first error code is preserved when both rollback phases fail.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTaskRollback011, TestSize.Level0)
{
    std::vector<BriefPermData> oldBrief = BuildBriefList(1); // 1: granted opcode
    std::vector<RemoveSpmDataParam> params = { { 0x31A, &oldBrief } };
    GetFakeSpmKernelState().addRet = RET_FAILED;
    GetFakeSpmKernelState().addPermRet = RET_FAILED;

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    ASSERT_EQ(RET_SUCCESS, task.Remove(errIndex));
    // both phases failed: the entry error (first) is preserved
    EXPECT_EQ(ERR_KERNEL_COMMON_FAILED, task.Rollback());
    EXPECT_EQ(2, GetFakeSpmKernelState().addCallCount);
    EXPECT_EQ(2, GetFakeSpmKernelState().addPermCallCount);
}

/**
 * @tc.name: RemoveSpmDataTask005
 * @tc.desc: Verify kernel not supported skips spm capture/restore but still restores caller-provided perms.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTask005, TestSize.Level0)
{
    std::vector<BriefPermData> oldBrief = BuildBriefList(3); // 3: granted opcode
    std::vector<RemoveSpmDataParam> params = { { 0x30B, &oldBrief } };
    GetFakeSpmKernelState().getVersionRet = ENOTSUP;

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    ASSERT_EQ(RET_SUCCESS, task.Remove(errIndex));
    EXPECT_EQ(0, GetFakeSpmKernelState().getCallCount);
    EXPECT_EQ(0, GetFakeSpmKernelState().getPermsCallCount);
    EXPECT_EQ(1, GetFakeSpmKernelState().removePermCallCount);
    EXPECT_EQ(0, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    EXPECT_EQ(0, GetFakeSpmKernelState().addCallCount);
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount); // perms restorable without SPM support
}

/**
 * @tc.name: RemoveSpmDataTask006
 * @tc.desc: Verify perm removal failure is evented per token and stays best-effort.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTask006, TestSize.Level0)
{
    std::vector<RemoveSpmDataParam> params = { { 0x30C, nullptr }, { 0x30D, nullptr } };
    GetFakeSpmKernelState().removePermRet = RET_FAILED;

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Remove(errIndex));
    EXPECT_EQ(0u, errIndex); // first failure index
    // spm entries still removed
    EXPECT_EQ(2, GetFakeSpmKernelState().removeCallCount);
    // both perm removals failed after retry: 2 tokens x 2 calls
    EXPECT_EQ(4, GetFakeSpmKernelState().removePermCallCount);
}

/**
 * @tc.name: RemoveSpmDataTask007
 * @tc.desc: Verify both perm and spm entry removal failures are evented for one token.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTask007, TestSize.Level0)
{
    std::vector<RemoveSpmDataParam> params = { { 0x30E, nullptr } };
    GetFakeSpmKernelState().removeRet = RET_FAILED;
    GetFakeSpmKernelState().removePermRet = RET_FAILED;

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Remove(errIndex));
    EXPECT_EQ(0u, errIndex);
    // entry removal: initial + retry; perm removal: initial + retry
    EXPECT_EQ(2, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(2, GetFakeSpmKernelState().removePermCallCount);
}

/**
 * @tc.name: RemoveSpmDataTask008
 * @tc.desc: Verify errIndex reports the first failed entry when a later token fails.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, RemoveSpmDataTask008, TestSize.Level0)
{
    std::vector<RemoveSpmDataParam> params = { { 0x30F, nullptr }, { 0x310, nullptr } };
    // token 0x30F removed fine; token 0x310 fails entry removal even after retry
    GetFakeSpmKernelState().removeRetSequence = { RET_SUCCESS, RET_FAILED, RET_FAILED };

    RemoveSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Remove(errIndex));
    EXPECT_EQ(1u, errIndex); // first failure index
    EXPECT_EQ(3, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(2, GetFakeSpmKernelState().removePermCallCount);
}

/**
 * @tc.name: KernelAndDBTransaction001
 * @tc.desc: Verify StageKernelAdd -> CommitDb -> Commit commits kernel and database consistently.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, KernelAndDBTransaction001, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x311, "bundle.txn.one");
    std::vector<BriefPermData> brief = BuildBriefList(3); // 3: perm code
    BundleNoCachedInfo noCached = BuildNoCached();
    std::vector<PermissionWithValue> extendPerms;

    KernelAndDBWriteTransaction txn;
    EXPECT_TRUE(IsKernelAndDBWriteHeldByCurrentThread());
    ASSERT_EQ(RET_SUCCESS, txn.StageKernelAdd(BuildAddParams(hapInfo, brief, noCached, extendPerms)));
    EXPECT_EQ(1, GetFakeSpmKernelState().addCallCount);
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount);

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    ASSERT_EQ(RET_SUCCESS, txn.CommitDb(delInfoVec, addInfoVec));
    EXPECT_EQ(1u, GetMockDbState().deleteAndInsertCallCount);
    txn.Commit();
    EXPECT_TRUE(IsKernelAndDBWriteHeldByCurrentThread());
}

/**
 * @tc.name: KernelAndDBTransaction002
 * @tc.desc: Verify CommitDb failure triggers the destructor rollback of the staged kernel add.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, KernelAndDBTransaction002, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x312, "bundle.txn.two");
    std::vector<BriefPermData> brief = BuildBriefList(4); // 4: perm code
    BundleNoCachedInfo noCached = BuildNoCached();
    std::vector<PermissionWithValue> extendPerms;
    GetMockDbState().deleteAndInsertRet = AccessTokenError::ERR_DATABASE_OPERATE_FAILED;

    int32_t commitRet = RET_SUCCESS;
    {
        KernelAndDBWriteTransaction txn;
        ASSERT_EQ(RET_SUCCESS, txn.StageKernelAdd(BuildAddParams(hapInfo, brief, noCached, extendPerms)));
        commitRet = txn.CommitDb({ BuildDelInfo(0x312) }, {});
        EXPECT_EQ(AccessTokenError::ERR_DATABASE_OPERATE_FAILED, commitRet);
        EXPECT_EQ(1, GetFakeSpmKernelState().addCallCount);
        EXPECT_EQ(0, GetFakeSpmKernelState().removeCallCount);
    }
    // destructor rolled back the staged add: entry removed and permission data removed
    EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(static_cast<AccessTokenID>(0x312), GetFakeSpmKernelState().removedTokenIds[0]);
    EXPECT_EQ(1, GetFakeSpmKernelState().removePermCallCount);
    EXPECT_FALSE(IsKernelAndDBWriteHeldByCurrentThread());
}

/**
 * @tc.name: KernelAndDBTransaction003
 * @tc.desc: Verify StageKernelRemove -> CommitDb failure restores the captured kernel state (F5.4).
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, KernelAndDBTransaction003, TestSize.Level0)
{
    AccessTokenID tokenId = 0x313;
    std::vector<BriefPermData> oldBrief = BuildBriefList(6); // 6: granted opcode
    oldBrief.emplace_back(BuildBriefList(8)[0]);             // 8: granted opcode
    GetMockDbState().deleteAndInsertRet = AccessTokenError::ERR_DATABASE_OPERATE_FAILED;

    {
        KernelAndDBWriteTransaction txn;
        ASSERT_EQ(RET_SUCCESS, txn.StageKernelRemove({ { tokenId, &oldBrief } }));
        EXPECT_EQ(1, GetFakeSpmKernelState().getCallCount);     // capture entry
        EXPECT_EQ(0, GetFakeSpmKernelState().getPermsCallCount); // perms are caller-provided
        EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);   // remove entry
        EXPECT_EQ(1, GetFakeSpmKernelState().removePermCallCount); // remove perms
        EXPECT_EQ(AccessTokenError::ERR_DATABASE_OPERATE_FAILED,
            txn.CommitDb({ BuildDelInfo(tokenId) }, {}));
    }
    // destructor restored the pre-transaction kernel state
    EXPECT_EQ(1, GetFakeSpmKernelState().addCallCount);
    ASSERT_EQ(1u, GetFakeSpmKernelState().addTokenBatches.size());
    EXPECT_EQ(tokenId, GetFakeSpmKernelState().addTokenBatches[0][0]);
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount);
    ASSERT_EQ(1u, GetFakeSpmKernelState().addPermOpCodeBatches.size());
    EXPECT_EQ(2u, GetFakeSpmKernelState().addPermOpCodeBatches[0].size());
    EXPECT_EQ(6u, GetFakeSpmKernelState().addPermOpCodeBatches[0][0]);
    EXPECT_EQ(8u, GetFakeSpmKernelState().addPermOpCodeBatches[0][1]);
}

/**
 * @tc.name: KernelAndDBTransaction004
 * @tc.desc: Verify the transaction state machine rejects invalid operations (decision table).
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, KernelAndDBTransaction004, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x314, "bundle.txn.four");
    std::vector<BriefPermData> brief = BuildBriefList(2); // 2: perm code
    BundleNoCachedInfo noCached = BuildNoCached();
    std::vector<PermissionWithValue> extendPerms;

    // empty StageKernelRemove is a no-op success
    {
        KernelAndDBWriteTransaction txn;
        EXPECT_EQ(RET_SUCCESS, txn.StageKernelRemove({}));
    }
    // duplicate stage is rejected
    {
        KernelAndDBWriteTransaction txn;
        ASSERT_EQ(RET_SUCCESS, txn.StageKernelAdd(BuildAddParams(hapInfo, brief, noCached, extendPerms)));
        EXPECT_EQ(ERR_PARAM_INVALID, txn.StageKernelAdd(BuildAddParams(hapInfo, brief, noCached, extendPerms)));
    }
    // stage after Commit is rejected
    {
        KernelAndDBWriteTransaction txn;
        ASSERT_EQ(RET_SUCCESS, txn.StageKernelAdd(BuildAddParams(hapInfo, brief, noCached, extendPerms)));
        txn.Commit();
        EXPECT_EQ(ERR_PARAM_INVALID, txn.StageKernelAdd(BuildAddParams(hapInfo, brief, noCached, extendPerms)));
        EXPECT_EQ(ERR_PARAM_INVALID, txn.CommitDb({}, {}));
    }
    // CommitDb after Abort is rejected, Abort reports success
    {
        KernelAndDBWriteTransaction txn;
        ASSERT_EQ(RET_SUCCESS, txn.StageKernelAdd(BuildAddParams(hapInfo, brief, noCached, extendPerms)));
        EXPECT_EQ(RET_SUCCESS, txn.Abort());
        EXPECT_EQ(ERR_PARAM_INVALID, txn.CommitDb({}, {}));
        EXPECT_EQ(ERR_PARAM_INVALID, txn.Abort());
    }
}

/**
 * @tc.name: KernelAndDBTransaction005
 * @tc.desc: Verify nested construction is reported as a guard violation (test builds abort).
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, KernelAndDBTransaction005, TestSize.Level0)
{
    // gtest EXPECT_DEATH needs /tmp which does not exist on OHOS devices,
    // so verify the abort with a manual fork/waitpid pair.
    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        KernelAndDBWriteTransaction outer;
        // nested construction: no isolation of its own, guard violation
        KernelAndDBWriteTransaction inner;
        _exit(0); // only reached when the guard fails to abort
    }
    int status = 0;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    EXPECT_TRUE(WIFSIGNALED(status));
    EXPECT_EQ(SIGABRT, WTERMSIG(status));
}

/**
 * @tc.name: KernelAndDBTransaction007
 * @tc.desc: Verify Commit() after an unchecked CommitDb failure is rejected by the poison marker.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, KernelAndDBTransaction007, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x318, "bundle.txn.seven");
    std::vector<BriefPermData> brief = BuildBriefList(9); // 9: perm code
    // manual fork/waitpid instead of EXPECT_DEATH (no /tmp on OHOS devices)
    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        BundleNoCachedInfo noCached = BuildNoCached();
        std::vector<PermissionWithValue> extendPerms;
        GetMockDbState().deleteAndInsertRet = AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        KernelAndDBWriteTransaction txn;
        (void)txn.StageKernelAdd(BuildAddParams(hapInfo, brief, noCached, extendPerms));
        (void)txn.CommitDb({ BuildDelInfo(0x318) }, {});
        // unchecked CommitDb failure: Commit() is rejected with a guard violation
        txn.Commit();
        _exit(0); // only reached when the guard fails to abort
    }
    int status = 0;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    EXPECT_TRUE(WIFSIGNALED(status));
    EXPECT_EQ(SIGABRT, WTERMSIG(status));
}

/**
 * @tc.name: KernelAndDBTransaction008
 * @tc.desc: Verify StageKernelUpdate -> CommitDb failure rolls the kernel update back.
 * @tc.type: FUNC
 */
HWTEST_F(KernelAndDBTransactionTest, KernelAndDBTransaction008, TestSize.Level0)
{
    AccessTokenID tokenId = 0x319;
    HapTokenInfo hapInfo = BuildHapInfo(tokenId, "bundle.txn.eight");
    std::vector<BriefPermData> brief = BuildBriefList(11);    // 11: new perm code
    std::vector<BriefPermData> oldBrief = BuildBriefList(12); // 12: old perm code
    GetMockDbState().deleteAndInsertRet = AccessTokenError::ERR_DATABASE_OPERATE_FAILED;

    {
        KernelAndDBWriteTransaction txn;
        std::vector<PermissionWithValue> extendPerms;
        BundleNoCachedInfo noCached = BuildNoCached();
        SpmDataParam param{hapInfo, noCached, brief, extendPerms, &oldBrief, true};
        ASSERT_EQ(RET_SUCCESS, txn.StageKernelUpdate({ param }));
        EXPECT_EQ(1, GetFakeSpmKernelState().setCallCount);     // kernel entry updated
        EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount); // new perms applied
        EXPECT_EQ(AccessTokenError::ERR_DATABASE_OPERATE_FAILED, txn.CommitDb({ BuildDelInfo(tokenId) }, {}));
    }
    // destructor rolled the update back: old entry restored via Set, old perms re-applied
    EXPECT_EQ(2, GetFakeSpmKernelState().setCallCount);
    EXPECT_EQ(2, GetFakeSpmKernelState().addPermCallCount);
    EXPECT_FALSE(IsKernelAndDBWriteHeldByCurrentThread());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

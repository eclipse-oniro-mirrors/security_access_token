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

#include <algorithm>
#include <cerrno>
#include <gtest/gtest.h>

#include "access_token_error.h"
#include "add_spm_data_task.h"
#include "fake_token_setproc.h"
#include "permission_data_brief.h"
#include "permission_kernel_utils.h"
#include "securec.h"
#include "spm_data_kernel_common.h"
#include "update_spm_data_task.h"

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
}

class SpmDataTaskTest : public testing::Test {
public:
    void SetUp() override
    {
        ResetFakeSpmKernelState();
    }

    void TearDown() override
    {
        ResetFakeSpmKernelState();
    }
};

/**
 * @tc.name: AddSpmDataTask001
 * @tc.desc: Verify batch add reports success and calls add ioctl once.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddSpmDataTask001, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x101, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x102, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, nullptr, true },
        { hapInfo2, noCached2, brief2, extendPerms, nullptr, true },
    };

    AddSpmDataTask task(params);
    uint32_t errIndex = 99;
    ASSERT_EQ(RET_SUCCESS, task.Add(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(1, GetFakeSpmKernelState().addCallCount);
    EXPECT_EQ(2, GetFakeSpmKernelState().addPermCallCount);
}

/**
 * @tc.name: AddSpmDataTask002
 * @tc.desc: Verify invalid extended permission names are silently skipped and add succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddSpmDataTask002, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x103, "bundle.one");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<PermissionWithValue> invalidExtendPerms = { { "invalid.permission.name", "true" } };
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, invalidExtendPerms },
    };

    AddSpmDataTask task(params);
    uint32_t errIndex = 99;
    // Invalid permission names are silently skipped, build succeeds
    EXPECT_EQ(RET_SUCCESS, task.Add(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(0, GetFakeSpmKernelState().addPermCallCount);
    EXPECT_EQ(1, GetFakeSpmKernelState().addCallCount);
}

/**
 * @tc.name: AddSpmDataTask003
 * @tc.desc: Verify empty add task returns ERR_PARAM_INVALID.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddSpmDataTask003, TestSize.Level0)
{
    AddSpmDataTask task({});
    uint32_t errIndex = 99;
    EXPECT_EQ(ERR_PARAM_INVALID, task.Add(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(0, GetFakeSpmKernelState().addCallCount);
}

/**
 * @tc.name: AddSpmDataTask004
 * @tc.desc: Verify kernel not supported skips SPM operations but processes permissions.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddSpmDataTask004, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x103, "bundle.one");
    BundleNoCachedInfo noCached = BuildNoCached();
    std::vector<BriefPermData> brief = BuildBriefList(1);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo, noCached, brief, extendPerms, nullptr, true },
    };
    GetFakeSpmKernelState().getVersionRet = ENOTSUP;

    AddSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Add(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(0, GetFakeSpmKernelState().addCallCount);  // SpmAddEntries not called
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount);  // Permissions still processed
    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    EXPECT_EQ(0, GetFakeSpmKernelState().removeCallCount);  // SpmRemoveEntry not called
    EXPECT_EQ(1, GetFakeSpmKernelState().removePermCallCount);  // Permissions rolled back
}

/**
 * @tc.name: AddSpmDataTaskRollback001
 * @tc.desc: Verify rollback removes only successfully added tokens in reverse order.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddSpmDataTaskRollback001, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x103, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x104, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, nullptr, false },
        { hapInfo2, noCached2, brief2, extendPerms, nullptr, false },
    };
    GetFakeSpmKernelState().addRet = RET_FAILED;
    GetFakeSpmKernelState().addIdxErr = 1;

    AddSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(ERR_KERNEL_COMMON_FAILED, task.Add(errIndex));
    EXPECT_EQ(1u, errIndex);
    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    ASSERT_EQ(1, GetFakeSpmKernelState().removeCallCount);
    ASSERT_EQ(1u, GetFakeSpmKernelState().removedTokenIds.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x103), GetFakeSpmKernelState().removedTokenIds[0]);
    EXPECT_EQ(0, GetFakeSpmKernelState().removePermCallCount);
    // Verify idempotency: second rollback should have no additional effect
    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);
}

/**
 * @tc.name: AddSpmDataTaskRollback002
 * @tc.desc: Verify spm data add failure rolls back successfully added spm data.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddSpmDataTaskRollback002, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x10A, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x10B, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, nullptr, true },
        { hapInfo2, noCached2, brief2, extendPerms, nullptr, true },
    };
    GetFakeSpmKernelState().addRet = RET_FAILED;
    GetFakeSpmKernelState().addIdxErr = 1;

    AddSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(ERR_KERNEL_COMMON_FAILED, task.Add(errIndex));
    EXPECT_EQ(1u, errIndex);
    // Permissions are NOT processed when SPM fails (SPM is processed first)
    EXPECT_EQ(0u, GetFakeSpmKernelState().addPermTokenIds.size());
    // First SPM entry should be removed
    ASSERT_EQ(1u, GetFakeSpmKernelState().removedTokenIds.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x10A), GetFakeSpmKernelState().removedTokenIds[0]);
}

/**
 * @tc.name: AddSpmDataTaskPermRollback001
 * @tc.desc: Verify perm data sync failure rolls back both perms and spm entries.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddSpmDataTaskPermRollback001, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x115, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x116, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, nullptr, true },
        { hapInfo2, noCached2, brief2, extendPerms, nullptr, true },
    };
    GetFakeSpmKernelState().addPermRetSequence = { RET_SUCCESS, RET_FAILED, RET_FAILED };

    AddSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_FAILED, task.Add(errIndex));
    EXPECT_EQ(1u, errIndex);
    EXPECT_EQ(1, GetFakeSpmKernelState().addCallCount);  // SPM entries added in one batch
    EXPECT_EQ(3, GetFakeSpmKernelState().addPermCallCount);  // Perm sync for both items, second retried once
    // Perm rolled back for the first token only (second failed)
    ASSERT_EQ(1u, GetFakeSpmKernelState().removePermTokenIds.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x115), GetFakeSpmKernelState().removePermTokenIds[0]);
    // SPM entries rolled back in reverse order
    ASSERT_EQ(2u, GetFakeSpmKernelState().removedTokenIds.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x116), GetFakeSpmKernelState().removedTokenIds[0]);
    EXPECT_EQ(static_cast<AccessTokenID>(0x115), GetFakeSpmKernelState().removedTokenIds[1]);
}

/**
 * @tc.name: AddSpmDataTask005
 * @tc.desc: Verify mixed updateWithPerm configuration fails before touching kernel.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddSpmDataTask005, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x10E, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x10F, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, nullptr, false },
        { hapInfo2, noCached2, brief2, extendPerms, nullptr, true },
    };

    AddSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(ERR_PARAM_INVALID, task.Add(errIndex));
    EXPECT_EQ(0, GetFakeSpmKernelState().addCallCount);
    EXPECT_EQ(0, GetFakeSpmKernelState().addPermCallCount);
}

/**
 * @tc.name: AddSpmDataTask006
 * @tc.desc: Verify kernel not supported skips both SPM and permission sync when updateWithPerm is false.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddSpmDataTask006, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x110, "bundle.one");
    BundleNoCachedInfo noCached = BuildNoCached();
    std::vector<BriefPermData> brief = BuildBriefList(1);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo, noCached, brief, extendPerms, nullptr, false },
    };
    GetFakeSpmKernelState().getVersionRet = ENOTSUP;

    AddSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Add(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(0, GetFakeSpmKernelState().addCallCount);  // SpmAddEntries not called
    EXPECT_EQ(0, GetFakeSpmKernelState().addPermCallCount);  // Permissions not processed
    EXPECT_EQ(0, GetFakeSpmKernelState().removePermCallCount);
}

/**
 * @tc.name: UpdateSpmDataTask001
 * @tc.desc: Verify load failure fails before update phase and leaves errIndex 0.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTask001, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x104, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x105, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, &brief1, false },
        { hapInfo2, noCached2, brief2, extendPerms, &brief2, false },
    };
    GetFakeSpmKernelState().getRetOnCall0 = RET_SUCCESS;
    GetFakeSpmKernelState().getRetOnCall1 = RET_FAILED;

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(ERR_KERNEL_COMMON_FAILED, task.Update(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(2, GetFakeSpmKernelState().getCallCount);
}

/**
 * @tc.name: UpdateSpmDataTask002
 * @tc.desc: Verify update failure reports kernel error index and rollback uses reverse token order.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTask002, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x106, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x107, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, &brief1, false },
        { hapInfo2, noCached2, brief2, extendPerms, &brief2, false },
    };
    GetFakeSpmKernelState().setRet = RET_FAILED;
    GetFakeSpmKernelState().setIdxErr = 1;

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(ERR_KERNEL_COMMON_FAILED, task.Update(errIndex));
    EXPECT_EQ(1u, errIndex);
    // update full batch + internal retry, rollback restore + internal retry
    ASSERT_EQ(4u, GetFakeSpmKernelState().setTokenBatches.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x106), GetFakeSpmKernelState().setTokenBatches[0][0]);
    EXPECT_EQ(static_cast<AccessTokenID>(0x107), GetFakeSpmKernelState().setTokenBatches[0][1]);
    ASSERT_EQ(1u, GetFakeSpmKernelState().setTokenBatches[2].size());
    // Retry batch contains only the failed part (index 1 and later)
    EXPECT_EQ(static_cast<AccessTokenID>(0x107), GetFakeSpmKernelState().setTokenBatches[1][0]);
}

/**
 * @tc.name: UpdateSpmDataTask003
 * @tc.desc: Verify empty update task returns failure.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTask003, TestSize.Level0)
{
    UpdateSpmDataTask task({});
    uint32_t errIndex = 99;
    EXPECT_EQ(ERR_PARAM_INVALID, task.Update(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(0, GetFakeSpmKernelState().getCallCount);
    EXPECT_EQ(0, GetFakeSpmKernelState().setCallCount);
}

/**
 * @tc.name: UpdateSpmDataTask004
 * @tc.desc: Verify nullptr oldPerm builds, and a new token rolls back by removal.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTask004, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x111, "bundle.one");
    BundleNoCachedInfo noCached = BuildNoCached();
    std::vector<BriefPermData> brief = BuildBriefList(1);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo, noCached, brief, extendPerms, nullptr, true },
    };
    // new token (converged install): kernel has no entry and no old perms
    GetFakeSpmKernelState().getRetSequence = { ENODATA };

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Update(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(1, GetFakeSpmKernelState().getCallCount);
    EXPECT_EQ(1, GetFakeSpmKernelState().setCallCount);     // upsert created the entry
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount);

    // rollback of a no-old-perm token removes the entry and perm bitmap
    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    ASSERT_EQ(1u, GetFakeSpmKernelState().removedTokenIds.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x111), GetFakeSpmKernelState().removedTokenIds[0]);
    ASSERT_EQ(1u, GetFakeSpmKernelState().removePermTokenIds.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x111), GetFakeSpmKernelState().removePermTokenIds[0]);
    EXPECT_EQ(1, GetFakeSpmKernelState().setCallCount);     // no restore set batch
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount); // no restore perm call
}

/**
 * @tc.name: UpdateSpmDataTask005
 * @tc.desc: Verify mixed updateWithPerm configuration fails before touching kernel.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTask005, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x112, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x113, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, &brief1, false },
        { hapInfo2, noCached2, brief2, extendPerms, &brief2, true },
    };

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(ERR_PARAM_INVALID, task.Update(errIndex));
    EXPECT_EQ(0, GetFakeSpmKernelState().getCallCount);
    EXPECT_EQ(0, GetFakeSpmKernelState().setCallCount);
}

/**
 * @tc.name: UpdateSpmDataTask006
 * @tc.desc: Verify kernel not supported still updates permissions when updateWithPerm is true.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTask006, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x114, "bundle.one");
    BundleNoCachedInfo noCached = BuildNoCached();
    std::vector<BriefPermData> brief = BuildBriefList(1);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo, noCached, brief, extendPerms, &brief, true },
    };
    GetFakeSpmKernelState().getVersionRet = ENOTSUP;

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Update(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount);
    EXPECT_EQ(0, GetFakeSpmKernelState().setCallCount);
}

/**
 * @tc.name: UpdateSpmDataTask007
 * @tc.desc: Verify mixed batch rollback restores known old perms and removes unknown ones.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTask007, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x203, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x204, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, &brief1, true },
        { hapInfo2, noCached2, brief2, extendPerms, nullptr, true },
    };
    // token 0x203 has old data in kernel, token 0x204 is new (converged install)
    GetFakeSpmKernelState().getRetSequence = { RET_SUCCESS, ENODATA };

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Update(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(1, GetFakeSpmKernelState().setCallCount);
    EXPECT_EQ(2, GetFakeSpmKernelState().addPermCallCount);

    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    // entry phase: old data of 0x203 restored by set, new entry of 0x204 removed
    ASSERT_EQ(2u, GetFakeSpmKernelState().setTokenBatches.size());
    ASSERT_EQ(1u, GetFakeSpmKernelState().setTokenBatches[1].size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x203), GetFakeSpmKernelState().setTokenBatches[1][0]);
    ASSERT_EQ(1u, GetFakeSpmKernelState().removedTokenIds.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x204), GetFakeSpmKernelState().removedTokenIds[0]);
    // perm phase: 0x203 restored (3rd add perm call), 0x204 removed
    EXPECT_EQ(3, GetFakeSpmKernelState().addPermCallCount);
    ASSERT_EQ(1u, GetFakeSpmKernelState().removePermTokenIds.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x204), GetFakeSpmKernelState().removePermTokenIds[0]);
}

/**
 * @tc.name: UpdateSpmDataTask008
 * @tc.desc: Verify existing entry with unknown old perms restores the entry and removes perms.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTask008, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x205, "bundle.one");
    BundleNoCachedInfo noCached = BuildNoCached();
    std::vector<BriefPermData> brief = BuildBriefList(1);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo, noCached, brief, extendPerms, nullptr, true },
    };
    // entry exists but old perms are unknown (data gap): degraded compensation
    GetFakeSpmKernelState().getRetSequence = { RET_SUCCESS };

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Update(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(1, GetFakeSpmKernelState().setCallCount);
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount);

    // rollback restores the entry but removes the written perm bitmap
    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    EXPECT_EQ(2, GetFakeSpmKernelState().setCallCount);
    EXPECT_EQ(0u, GetFakeSpmKernelState().removedTokenIds.size());
    ASSERT_EQ(1u, GetFakeSpmKernelState().removePermTokenIds.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x205), GetFakeSpmKernelState().removePermTokenIds[0]);
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount); // no restore perm call
}

/**
 * @tc.name: UpdateSpmDataTask009
 * @tc.desc: Verify perm failure rollback removes perms of nullptr items written before it.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTask009, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x206, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x207, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, nullptr, true },
        { hapInfo2, noCached2, brief2, extendPerms, &brief2, true },
    };
    // item 0 perms applied, item 1 fails even after retry
    GetFakeSpmKernelState().addPermRetSequence = { RET_SUCCESS, RET_FAILED, RET_FAILED };

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_FAILED, task.Update(errIndex));
    EXPECT_EQ(1u, errIndex);
    // internal rollback restored both entries (both loaded old data)
    ASSERT_EQ(2u, GetFakeSpmKernelState().setTokenBatches.size());
    ASSERT_EQ(2u, GetFakeSpmKernelState().setTokenBatches[1].size());
    // only the nullptr item written before the failure is perm-removed
    EXPECT_EQ(3, GetFakeSpmKernelState().addPermCallCount);
    ASSERT_EQ(1u, GetFakeSpmKernelState().removePermTokenIds.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x206), GetFakeSpmKernelState().removePermTokenIds[0]);
}

/**
 * @tc.name: UpdateSpmDataTask010
 * @tc.desc: Verify perm removal failure during nullptr rollback is reported.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTask010, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x208, "bundle.one");
    BundleNoCachedInfo noCached = BuildNoCached();
    std::vector<BriefPermData> brief = BuildBriefList(1);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo, noCached, brief, extendPerms, nullptr, true },
    };
    GetFakeSpmKernelState().getRetSequence = { ENODATA };
    GetFakeSpmKernelState().removePermRet = RET_FAILED;

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Update(errIndex));
    EXPECT_EQ(0u, errIndex);

    // entry removal succeeds, perm removal fails even after retry
    EXPECT_EQ(RET_FAILED, task.Rollback());
    ASSERT_EQ(1u, GetFakeSpmKernelState().removedTokenIds.size());
    EXPECT_EQ(2, GetFakeSpmKernelState().removePermCallCount);
}

/**
 * @tc.name: UpdateSpmDataTaskRollback001
 * @tc.desc: Verify explicit rollback restores loaded old spm data in reverse order.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTaskRollback001, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x108, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x109, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, &brief1, false },
        { hapInfo2, noCached2, brief2, extendPerms, &brief2, false },
    };
    GetFakeSpmKernelState().setRet = RET_FAILED;
    GetFakeSpmKernelState().setIdxErr = 1;

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    // [0x108, 0x109] [0x109] [0x108] [0x108]
    EXPECT_EQ(ERR_KERNEL_COMMON_FAILED, task.Update(errIndex));
    EXPECT_EQ(1u, errIndex);
    ASSERT_EQ(4u, GetFakeSpmKernelState().setTokenBatches.size());
    ASSERT_EQ(1u, GetFakeSpmKernelState().setTokenBatches[2].size());
    // Retry batch contains only the failed part (index 1 and later)
    EXPECT_EQ(static_cast<AccessTokenID>(0x109), GetFakeSpmKernelState().setTokenBatches[1][0]);
    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    ASSERT_EQ(4u, GetFakeSpmKernelState().setTokenBatches.size());
}

/**
 * @tc.name: UpdateSpmDataTaskRollback002
 * @tc.desc: Verify spm data set failure rolls back updated spm data.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTaskRollback002, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x10C, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x10D, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, &brief1, true },
        { hapInfo2, noCached2, brief2, extendPerms, &brief2, true },
    };
    GetFakeSpmKernelState().setRet = RET_FAILED;
    GetFakeSpmKernelState().setIdxErr = 1;

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(ERR_KERNEL_COMMON_FAILED, task.Update(errIndex));
    EXPECT_EQ(1u, errIndex);
    // Four calls: Update full batch (fails) + internal retry (fails),
    // rollback restore (fails) + internal retry (fails)
    ASSERT_EQ(4u, GetFakeSpmKernelState().setTokenBatches.size());
    // First call: tried to set new data for both tokens
    ASSERT_EQ(2u, GetFakeSpmKernelState().setTokenBatches[0].size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x10C), GetFakeSpmKernelState().setTokenBatches[0][0]);
    EXPECT_EQ(static_cast<AccessTokenID>(0x10D), GetFakeSpmKernelState().setTokenBatches[0][1]);
    // Second call (Rollback): restores old data for first token only (index1 failed)
    ASSERT_EQ(1u, GetFakeSpmKernelState().setTokenBatches[2].size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x10C), GetFakeSpmKernelState().setTokenBatches[2][0]);
}

/**
 * @tc.name: UpdateSpmDataTaskPermRollback001
 * @tc.desc: Verify perm update failure rolls back spm data and restores old perms.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTaskPermRollback001, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x117, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x118, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, &brief1, true },
        { hapInfo2, noCached2, brief2, extendPerms, &brief2, true },
    };
    GetFakeSpmKernelState().addPermRetSequence = { RET_SUCCESS, RET_FAILED, RET_FAILED };

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_FAILED, task.Update(errIndex));
    EXPECT_EQ(1u, errIndex);
    // Two set batches: new data, then rollback restoring old data for both tokens
    ASSERT_EQ(2u, GetFakeSpmKernelState().setTokenBatches.size());
    ASSERT_EQ(2u, GetFakeSpmKernelState().setTokenBatches[0].size());
    ASSERT_EQ(2u, GetFakeSpmKernelState().setTokenBatches[1].size());
    // Perm update for both items (second retried once), rollback restores old perms for the first token
    EXPECT_EQ(4, GetFakeSpmKernelState().addPermCallCount);
    ASSERT_EQ(4u, GetFakeSpmKernelState().addPermTokenIds.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x117), GetFakeSpmKernelState().addPermTokenIds[3]);
    // Update rollback restores by set, not by remove
    EXPECT_EQ(0, GetFakeSpmKernelState().removeCallCount);
    EXPECT_EQ(0, GetFakeSpmKernelState().removePermCallCount);
}

/**
 * @tc.name: AddSpmDataTaskEEXIST001
 * @tc.desc: Verify EEXIST error returns ERR_DATA_CONFLICT_WITH_KERNEL.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddSpmDataTaskEEXIST001, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x200, "bundle.one");
    BundleNoCachedInfo noCached = BuildNoCached();
    std::vector<BriefPermData> brief = BuildBriefList(1);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo, noCached, brief, extendPerms, nullptr, false },
    };
    GetFakeSpmKernelState().addRet = EEXIST;
    GetFakeSpmKernelState().addIdxErr = 0;

    AddSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(AccessTokenError::ERR_DATA_CONFLICT_WITH_KERNEL, task.Add(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(1, GetFakeSpmKernelState().addCallCount);
}

/**
 * @tc.name: AddSpmDataTaskENOTSUP001
 * @tc.desc: Verify kernel not supported (getVersionRet=ENOTSUP) is treated as success.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddSpmDataTaskENOTSUP001, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x201, "bundle.one");
    BundleNoCachedInfo noCached = BuildNoCached();
    std::vector<BriefPermData> brief = BuildBriefList(1);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo, noCached, brief, extendPerms, nullptr, false },
    };
    GetFakeSpmKernelState().getVersionRet = ENOTSUP;

    AddSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Add(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(0, GetFakeSpmKernelState().addCallCount);  // SpmAddEntries not called
}

/**
 * @tc.name: UpdateSpmDataTaskENODATA001
 * @tc.desc: Verify ENODATA in load is treated as no old data and rollback removes the new entry.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTaskENODATA001, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x202, "bundle.one");
    BundleNoCachedInfo noCached = BuildNoCached();
    std::vector<BriefPermData> brief = BuildBriefList(1);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo, noCached, brief, extendPerms, &brief, false },
    };
    GetFakeSpmKernelState().getRetSequence = { ENODATA };

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Update(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(1, GetFakeSpmKernelState().getCallCount);
    EXPECT_EQ(1, GetFakeSpmKernelState().setCallCount);  // new data set

    // rollback removes the entry of a token that had no old data
    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    ASSERT_EQ(1u, GetFakeSpmKernelState().removedTokenIds.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x202), GetFakeSpmKernelState().removedTokenIds[0]);
    EXPECT_EQ(1, GetFakeSpmKernelState().setCallCount);  // no set batches during rollback
}

/**
 * @tc.name: UpdateSpmDataTaskENODATA002
 * @tc.desc: Verify rollback restores old data for loaded tokens and removes entries for ENODATA tokens.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTaskENODATA002, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x321, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x322, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, &brief1, false },
        { hapInfo2, noCached2, brief2, extendPerms, &brief2, false },
    };
    // token 0x321 has old data in kernel, token 0x322 has none (new token first update)
    GetFakeSpmKernelState().getRetSequence = { RET_SUCCESS, ENODATA };

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Update(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(2, GetFakeSpmKernelState().getCallCount);

    EXPECT_EQ(RET_SUCCESS, task.Rollback());
    // rollback restores old data of 0x321 by set and removes the new entry of 0x322
    ASSERT_EQ(2u, GetFakeSpmKernelState().setTokenBatches.size());
    ASSERT_EQ(1u, GetFakeSpmKernelState().setTokenBatches[1].size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x321), GetFakeSpmKernelState().setTokenBatches[1][0]);
    ASSERT_EQ(1u, GetFakeSpmKernelState().removedTokenIds.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x322), GetFakeSpmKernelState().removedTokenIds[0]);
}

/**
 * @tc.name: UpdateSpmDataTaskEEXIST001
 * @tc.desc: Verify SetSpmEntries EEXIST error returns ERR_DATA_CONFLICT_WITH_KERNEL.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTaskEEXIST001, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x203, "bundle.one");
    BundleNoCachedInfo noCached = BuildNoCached();
    std::vector<BriefPermData> brief = BuildBriefList(1);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo, noCached, brief, extendPerms, &brief, false },
    };
    GetFakeSpmKernelState().setRet = EEXIST;
    GetFakeSpmKernelState().setIdxErr = 0;

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(AccessTokenError::ERR_DATA_CONFLICT_WITH_KERNEL, task.Update(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(1, GetFakeSpmKernelState().setCallCount);
}

/**
 * @tc.name: UpdateSpmDataTaskENOTSUP001
 * @tc.desc: Verify SetSpmEntries ENOTSUP error causes Update to fail with ERR_IOCTL_UNSUPPORT.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTaskENOTSUP001, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x204, "bundle.one");
    BundleNoCachedInfo noCached = BuildNoCached();
    std::vector<BriefPermData> brief = BuildBriefList(1);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo, noCached, brief, extendPerms, &brief, false },
    };
    GetFakeSpmKernelState().setRet = ENOTSUP;

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(AccessTokenError::ERR_IOCTL_UNSUPPORT, task.Update(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(1, GetFakeSpmKernelState().setCallCount);
}

/**
 * @tc.name: AddSpmDataTaskSequence001
 * @tc.desc: Verify addRetSequence works correctly for multiple calls.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddSpmDataTaskSequence001, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x205, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x206, "bundle.two");
    HapTokenInfo hapInfo3 = BuildHapInfo(0x207, "bundle.three");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    BundleNoCachedInfo noCached3 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<BriefPermData> brief3 = BuildBriefList(3);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params1 = {
        { hapInfo1, noCached1, brief1, extendPerms, nullptr, false },
    };
    std::vector<SpmDataParam> params2 = {
        { hapInfo2, noCached2, brief2, extendPerms, nullptr, false },
    };
    std::vector<SpmDataParam> params3 = {
        { hapInfo3, noCached3, brief3, extendPerms, nullptr, false },
    };

    GetFakeSpmKernelState().addRetSequence = { RET_SUCCESS, EEXIST, RET_FAILED, RET_FAILED };

    AddSpmDataTask task1(params1);
    uint32_t errIndex1 = 99;
    EXPECT_EQ(RET_SUCCESS, task1.Add(errIndex1));
    EXPECT_EQ(0u, errIndex1);

    AddSpmDataTask task2(params2);
    uint32_t errIndex2 = 99;
    EXPECT_EQ(AccessTokenError::ERR_DATA_CONFLICT_WITH_KERNEL, task2.Add(errIndex2));
    EXPECT_EQ(0u, errIndex2);

    // Third call should use RET_FAILED
    AddSpmDataTask task3(params3);
    uint32_t errIndex3 = 99;
    EXPECT_EQ(ERR_KERNEL_COMMON_FAILED, task3.Add(errIndex3));
    EXPECT_EQ(0u, errIndex3);
}

/**
 * @tc.name: BuildExtendedPermissionBuffer001
 * @tc.desc: Verify BuildExtendedPermissionBuffer handles empty permission list.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, BuildExtendedPermissionBuffer001, TestSize.Level0)
{
    std::vector<PermissionWithValue> emptyList;
    std::vector<uint8_t> buffer;

    KernelDetail::BuildExtendedPermissionBuffer(emptyList, buffer);

    EXPECT_EQ(0u, buffer.size());
}

/**
 * @tc.name: BuildExtendedPermissionBuffer002
 * @tc.desc: Verify BuildExtendedPermissionBuffer correctly builds buffer for single permission.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, BuildExtendedPermissionBuffer002, TestSize.Level0)
{
    std::vector<PermissionWithValue> permList = { { "ohos.permission.INTERNET", "true" } };
    std::vector<uint8_t> buffer;

    KernelDetail::BuildExtendedPermissionBuffer(permList, buffer);

    // Verify buffer layout: [opCode(4 bytes)][valueSize(4 bytes)][value bytes][null terminator]
    EXPECT_GE(buffer.size(), sizeof(uint32_t) * 2 + 5); // opCode + size + "true" + '\0'

    // Parse and verify opCode
    uint32_t opCode = 0;
    (void)memcpy_s(&opCode, sizeof(uint32_t), buffer.data(), sizeof(uint32_t));
    EXPECT_NE(0u, opCode); // Valid permission should have non-zero opCode

    // Parse and verify valueSize
    uint32_t valueSize = 0;
    (void)memcpy_s(&valueSize, sizeof(uint32_t), buffer.data() + sizeof(uint32_t), sizeof(uint32_t));
    EXPECT_EQ(5u, valueSize); // "true" + '\0'
}

/**
 * @tc.name: BuildExtendedPermissionBuffer003
 * @tc.desc: Verify BuildExtendedPermissionBuffer correctly builds buffer for multiple permissions.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, BuildExtendedPermissionBuffer003, TestSize.Level0)
{
    std::vector<PermissionWithValue> permList = {
        { "ohos.permission.INTERNET", "true" },
        { "ohos.permission.GET_NETWORK_INFO", "false" }
    };
    std::vector<uint8_t> buffer;

    KernelDetail::BuildExtendedPermissionBuffer(permList, buffer);

    // Should have 2 entries
    size_t offset = 0;
    uint32_t entryCount = 0;

    while (offset + sizeof(uint32_t) * 2 <= buffer.size()) {
        uint32_t valueSize = 0;
        (void)memcpy_s(&valueSize, sizeof(uint32_t), buffer.data() + offset + sizeof(uint32_t),
            sizeof(uint32_t));
        if (valueSize == 0 || offset + sizeof(uint32_t) * 2 + valueSize > buffer.size()) {
            break;
        }
        offset += sizeof(uint32_t) * 2 + valueSize;
        entryCount++;
    }

    EXPECT_EQ(2u, entryCount);
}

/**
 * @tc.name: BuildExtendedPermissionBuffer004
 * @tc.desc: Verify BuildExtendedPermissionBuffer skips invalid permission names.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, BuildExtendedPermissionBuffer004, TestSize.Level0)
{
    std::vector<PermissionWithValue> permList = { { "invalid.permission.name", "value" } };
    std::vector<uint8_t> buffer;

    KernelDetail::BuildExtendedPermissionBuffer(permList, buffer);

    // Invalid permission names are skipped, so buffer should be empty
    EXPECT_EQ(0u, buffer.size());
}

/**
 * @tc.name: BuildExtendedPermissionBuffer005
 * @tc.desc: Verify BuildExtendedPermissionBuffer handles permission with empty value.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, BuildExtendedPermissionBuffer005, TestSize.Level0)
{
    std::vector<PermissionWithValue> permList = { { "ohos.permission.INTERNET", "" } };
    std::vector<uint8_t> buffer;

    KernelDetail::BuildExtendedPermissionBuffer(permList, buffer);

    // Verify buffer layout: [opCode(4 bytes)][valueSize(4 bytes)][null terminator only]
    EXPECT_GE(buffer.size(), sizeof(uint32_t) * 2 + 1); // opCode + size + '\0'

    uint32_t valueSize = 0;
    (void)memcpy_s(&valueSize, sizeof(uint32_t), buffer.data() + sizeof(uint32_t), sizeof(uint32_t));
    EXPECT_EQ(1u, valueSize); // Only '\0'
}

/**
 * @tc.name: BuildExtendedPermissionBuffer006
 * @tc.desc: Verify BuildExtendedPermissionBuffer handles special characters in value.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, BuildExtendedPermissionBuffer006, TestSize.Level0)
{
    std::string specialValue = "value_with_特殊_chars_🔥";
    std::vector<PermissionWithValue> permList = { { "ohos.permission.INTERNET", specialValue } };
    std::vector<uint8_t> buffer;

    KernelDetail::BuildExtendedPermissionBuffer(permList, buffer);

    // Verify value size includes null terminator
    uint32_t valueSize = 0;
    (void)memcpy_s(&valueSize, sizeof(uint32_t), buffer.data() + sizeof(uint32_t), sizeof(uint32_t));
    EXPECT_EQ(specialValue.size() + 1, valueSize);
}

/**
 * @tc.name: ParseExtendedPermissionBuffer001
 * @tc.desc: Verify ParseExtendedPermissionBuffer handles empty buffer.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, ParseExtendedPermissionBuffer001, TestSize.Level0)
{
    SpmBlob blob = { nullptr, 0 };
    std::vector<PermissionWithValue> permList;

    int32_t ret = KernelDetail::ParseExtendedPermissionBuffer(blob, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(0u, permList.size());
}

/**
 * @tc.name: ParseExtendedPermissionBuffer002
 * @tc.desc: Verify ParseExtendedPermissionBuffer correctly parses single permission.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, ParseExtendedPermissionBuffer002, TestSize.Level0)
{
    // Build a buffer manually
    std::vector<uint8_t> buffer;
    uint32_t opCode = 1; // Assume opCode 1 maps to some permission
    uint32_t valueSize = 5; // "test" + '\0'
    std::string value = "test";

    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&opCode),
                  reinterpret_cast<uint8_t*>(&opCode) + sizeof(uint32_t));
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&valueSize),
                  reinterpret_cast<uint8_t*>(&valueSize) + sizeof(uint32_t));
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(value.data()),
                  reinterpret_cast<const uint8_t*>(value.data()) + value.size());
    buffer.push_back('\0');

    SpmBlob blob = { reinterpret_cast<char*>(buffer.data()), buffer.size() };
    std::vector<PermissionWithValue> permList;

    int32_t ret = KernelDetail::ParseExtendedPermissionBuffer(blob, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(1u, permList.size());
}

/**
 * @tc.name: ParseExtendedPermissionBuffer003
 * @tc.desc: Verify ParseExtendedPermissionBuffer handles invalid value size.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, ParseExtendedPermissionBuffer003, TestSize.Level0)
{
    std::vector<uint8_t> buffer;
    uint32_t opCode = 1;
    uint32_t invalidValueSize = 9999; // Much larger than buffer size

    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&opCode),
                  reinterpret_cast<uint8_t*>(&opCode) + sizeof(uint32_t));
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&invalidValueSize),
                  reinterpret_cast<uint8_t*>(&invalidValueSize) + sizeof(uint32_t));

    SpmBlob blob = { reinterpret_cast<char*>(buffer.data()), buffer.size() };
    std::vector<PermissionWithValue> permList;

    int32_t ret = KernelDetail::ParseExtendedPermissionBuffer(blob, permList);

    EXPECT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: ParseExtendedPermissionBuffer004
 * @tc.desc: Verify ParseExtendedPermissionBuffer handles zero value size.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, ParseExtendedPermissionBuffer004, TestSize.Level0)
{
    std::vector<uint8_t> buffer;
    uint32_t opCode = 1;
    uint32_t zeroValueSize = 0;

    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&opCode),
                  reinterpret_cast<uint8_t*>(&opCode) + sizeof(uint32_t));
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&zeroValueSize),
                  reinterpret_cast<uint8_t*>(&zeroValueSize) + sizeof(uint32_t));

    SpmBlob blob = { reinterpret_cast<char*>(buffer.data()), buffer.size() };
    std::vector<PermissionWithValue> permList;

    int32_t ret = KernelDetail::ParseExtendedPermissionBuffer(blob, permList);

    EXPECT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: ParseExtendedPermissionBuffer005
 * @tc.desc: Verify ParseExtendedPermissionBuffer force-terminates value without null terminator.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, ParseExtendedPermissionBuffer005, TestSize.Level0)
{
    std::vector<uint8_t> buffer;
    uint32_t opCode = 1; // Assume opCode 1 maps to some permission
    uint32_t valueSize = 5; // "test" + terminator claimed
    std::string value = "test";

    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&opCode),
                  reinterpret_cast<uint8_t*>(&opCode) + sizeof(uint32_t));
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&valueSize),
                  reinterpret_cast<uint8_t*>(&valueSize) + sizeof(uint32_t));
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(value.data()),
                  reinterpret_cast<const uint8_t*>(value.data()) + value.size());
    buffer.push_back('X'); // last byte is not '\0', corrupted payload

    SpmBlob blob = { reinterpret_cast<char*>(buffer.data()), buffer.size() };
    std::vector<PermissionWithValue> permList;

    int32_t ret = KernelDetail::ParseExtendedPermissionBuffer(blob, permList);

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(1u, permList.size());
    EXPECT_EQ(value, permList[0].value);
    EXPECT_EQ('\0', buffer[8 + 4]); // force-terminated in place
}

/**
 * @tc.name: IsKernelSupportSpm001
 * @tc.desc: Verify IsKernelSupportSpm distinguishes success, not supported and other failures.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, IsKernelSupportSpm001, TestSize.Level0)
{
    GetFakeSpmKernelState().getVersionRet = 0; // 0: success
    EXPECT_TRUE(PermissionKernelUtils::IsKernelSupportSpm());

    GetFakeSpmKernelState().getVersionRet = ENOTSUP;
    EXPECT_FALSE(PermissionKernelUtils::IsKernelSupportSpm());

    GetFakeSpmKernelState().getVersionRet = EINVAL;
    EXPECT_FALSE(PermissionKernelUtils::IsKernelSupportSpm());
}

/**
 * @tc.name: AddNativePermToKernelInvalidParam001
 * @tc.desc: Verify AddNativePermToKernel rejects mismatched opCodeList/statusList sizes.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddNativePermToKernelInvalidParam001, TestSize.Level0)
{
    AccessTokenID tokenId = 0x300;
    std::vector<uint32_t> opCodeList = {1, 2};
    std::vector<bool> shortStatusList = {true};

    EXPECT_EQ(ERR_PARAM_INVALID, PermissionKernelUtils::AddNativePermToKernel(tokenId, opCodeList, shortStatusList));
    EXPECT_EQ(0, GetFakeSpmKernelState().addPermCallCount);  // kernel not touched

    std::vector<bool> statusList = {true, false};
    EXPECT_EQ(RET_SUCCESS, PermissionKernelUtils::AddNativePermToKernel(tokenId, opCodeList, statusList));
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount);
    ASSERT_EQ(1u, GetFakeSpmKernelState().addPermTokenIds.size());
    EXPECT_EQ(tokenId, GetFakeSpmKernelState().addPermTokenIds[0]);
}

/**
 * @tc.name: AddNativePermToKernelRetry001
 * @tc.desc: Verify transient native perm sync failure is retried once and succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddNativePermToKernelRetry001, TestSize.Level0)
{
    AccessTokenID tokenId = 0x315;
    std::vector<uint32_t> opCodeList = {1};
    std::vector<bool> statusList = {true};
    // first call fails transiently, retry succeeds
    GetFakeSpmKernelState().addPermRetSequence = { RET_FAILED, RET_SUCCESS };

    EXPECT_EQ(RET_SUCCESS, PermissionKernelUtils::AddNativePermToKernel(tokenId, opCodeList, statusList));
    EXPECT_EQ(2, GetFakeSpmKernelState().addPermCallCount);
}

/**
 * @tc.name: AddNativePermToKernelRetry002
 * @tc.desc: Verify native perm sync failure is retried once and still fails.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddNativePermToKernelRetry002, TestSize.Level0)
{
    AccessTokenID tokenId = 0x316;
    std::vector<uint32_t> opCodeList = {1};
    std::vector<bool> statusList = {true};
    GetFakeSpmKernelState().addPermRetSequence = { RET_FAILED, RET_FAILED };

    EXPECT_EQ(RET_FAILED, PermissionKernelUtils::AddNativePermToKernel(tokenId, opCodeList, statusList));
    EXPECT_EQ(2, GetFakeSpmKernelState().addPermCallCount);
    ASSERT_EQ(2u, GetFakeSpmKernelState().addPermTokenIds.size());
    EXPECT_EQ(tokenId, GetFakeSpmKernelState().addPermTokenIds[1]);
}

/**
 * @tc.name: AddSpmDataTaskRetryPartial001
 * @tc.desc: Verify SpmAddEntries retry only resubmits the failed part and succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddSpmDataTaskRetryPartial001, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x301, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x302, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, nullptr, false },
        { hapInfo2, noCached2, brief2, extendPerms, nullptr, false },
    };
    GetFakeSpmKernelState().addRetSequence = { RET_FAILED, RET_SUCCESS };
    GetFakeSpmKernelState().addIdxErr = 1;

    AddSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Add(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(2, GetFakeSpmKernelState().addCallCount);
    // first call submits all entries, retry submits only the failed part
    ASSERT_EQ(2u, GetFakeSpmKernelState().addTokenBatches.size());
    ASSERT_EQ(2u, GetFakeSpmKernelState().addTokenBatches[0].size());
    ASSERT_EQ(1u, GetFakeSpmKernelState().addTokenBatches[1].size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x302), GetFakeSpmKernelState().addTokenBatches[1][0]);
}

/**
 * @tc.name: AddSpmDataTaskRetryPartial002
 * @tc.desc: Verify retry failure reports absolute error index and rolls back added entries.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddSpmDataTaskRetryPartial002, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x303, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x304, "bundle.two");
    HapTokenInfo hapInfo3 = BuildHapInfo(0x305, "bundle.three");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    BundleNoCachedInfo noCached3 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<BriefPermData> brief3 = BuildBriefList(3);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, nullptr, false },
        { hapInfo2, noCached2, brief2, extendPerms, nullptr, false },
        { hapInfo3, noCached3, brief3, extendPerms, nullptr, false },
    };
    // first call fails at index 1, retry of the remaining 2 fails at relative index 1
    GetFakeSpmKernelState().addRetSequence = { RET_FAILED, RET_FAILED };
    GetFakeSpmKernelState().addIdxErr = 1;

    AddSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(ERR_KERNEL_COMMON_FAILED, task.Add(errIndex));
    // absolute index = failedIdx(1) + relative retry index(1) = 2
    EXPECT_EQ(2u, errIndex);
    ASSERT_EQ(2u, GetFakeSpmKernelState().addTokenBatches.size());
    ASSERT_EQ(2u, GetFakeSpmKernelState().addTokenBatches[1].size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x304), GetFakeSpmKernelState().addTokenBatches[1][0]);
    // rollback removes the 2 successfully added entries in reverse order
    ASSERT_EQ(2u, GetFakeSpmKernelState().removedTokenIds.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x304), GetFakeSpmKernelState().removedTokenIds[0]);
    EXPECT_EQ(static_cast<AccessTokenID>(0x303), GetFakeSpmKernelState().removedTokenIds[1]);
}

/**
 * @tc.name: UpdateSpmDataTaskRetryPartial001
 * @tc.desc: Verify SpmSetEntries retry only resubmits the failed part.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTaskRetryPartial001, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x306, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x307, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, &brief1, false },
        { hapInfo2, noCached2, brief2, extendPerms, &brief2, false },
    };
    GetFakeSpmKernelState().setRetSequence = { RET_FAILED, RET_SUCCESS };
    GetFakeSpmKernelState().setIdxErr = 1;

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Update(errIndex));
    EXPECT_EQ(0u, errIndex);
    ASSERT_EQ(2u, GetFakeSpmKernelState().setTokenBatches.size());
    ASSERT_EQ(2u, GetFakeSpmKernelState().setTokenBatches[0].size());
    ASSERT_EQ(1u, GetFakeSpmKernelState().setTokenBatches[1].size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x307), GetFakeSpmKernelState().setTokenBatches[1][0]);
}

/**
 * @tc.name: RemoveSpmEntryRetCode001
 * @tc.desc: Verify RemoveSpmEntryFromKernel returns error codes and retries only on failure.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, RemoveSpmEntryRetCode001, TestSize.Level0)
{
    AccessTokenID tokenId = 0x310;

    GetFakeSpmKernelState().removeRet = 0; // 0: success
    EXPECT_EQ(RET_SUCCESS, KernelDetail::RemoveSpmEntryFromKernel(tokenId));
    EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);

    ResetFakeSpmKernelState();
    GetFakeSpmKernelState().removeRet = ENODATA; // benign: no retry
    EXPECT_EQ(RET_SUCCESS, KernelDetail::RemoveSpmEntryFromKernel(tokenId));
    EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);

    ResetFakeSpmKernelState();
    GetFakeSpmKernelState().removeRet = ENOTSUP; // benign: no retry
    EXPECT_EQ(RET_SUCCESS, KernelDetail::RemoveSpmEntryFromKernel(tokenId));
    EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);

    ResetFakeSpmKernelState();
    GetFakeSpmKernelState().removeRet = RET_FAILED; // retry once then fail
    EXPECT_EQ(ERR_KERNEL_COMMON_FAILED, KernelDetail::RemoveSpmEntryFromKernel(tokenId));
    EXPECT_EQ(2, GetFakeSpmKernelState().removeCallCount);

    ResetFakeSpmKernelState();
    GetFakeSpmKernelState().removeRetSequence = { RET_FAILED, RET_SUCCESS }; // retry succeeds
    EXPECT_EQ(RET_SUCCESS, KernelDetail::RemoveSpmEntryFromKernel(tokenId));
    EXPECT_EQ(2, GetFakeSpmKernelState().removeCallCount);

    // wrapper passthrough (SPM_DATA_ENABLE is on in this test binary)
    ResetFakeSpmKernelState();
    GetFakeSpmKernelState().removeRet = RET_FAILED;
    EXPECT_EQ(ERR_KERNEL_COMMON_FAILED, PermissionKernelUtils::RemoveSpmEntryFromKernel(tokenId));
}

/**
 * @tc.name: UpdateSpmDataTaskPermRetry001
 * @tc.desc: Verify transient perm sync failure is retried once and succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTaskPermRetry001, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x311, "bundle.one");
    BundleNoCachedInfo noCached = BuildNoCached();
    std::vector<BriefPermData> brief = BuildBriefList(1);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo, noCached, brief, extendPerms, &brief, true },
    };
    // first perm sync call fails transiently, retry succeeds
    GetFakeSpmKernelState().addPermRetSequence = { RET_FAILED, RET_SUCCESS };

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Update(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(2, GetFakeSpmKernelState().addPermCallCount);
}

/**
 * @tc.name: UpdateSpmDataTaskRollbackRetry001
 * @tc.desc: Verify rollback retries the failed spm restore batch and succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTaskRollbackRetry001, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x312, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x313, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, &brief1, false },
        { hapInfo2, noCached2, brief2, extendPerms, &brief2, false },
    };
    // update full batch fails, internal retry fails, rollback restore fails,
    // then its internal retry succeeds
    GetFakeSpmKernelState().setRetSequence = { RET_FAILED, RET_FAILED, RET_FAILED, RET_SUCCESS };
    GetFakeSpmKernelState().setIdxErr = 1;

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(ERR_KERNEL_COMMON_FAILED, task.Update(errIndex));
    EXPECT_EQ(1u, errIndex);
    ASSERT_EQ(4u, GetFakeSpmKernelState().setTokenBatches.size());
    ASSERT_EQ(1u, GetFakeSpmKernelState().setTokenBatches[3].size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x312), GetFakeSpmKernelState().setTokenBatches[3][0]);
}

/**
 * @tc.name: BuildSpmDataExtendPermsLimit001
 * @tc.desc: Verify extend perms buffer beyond kernel read limit is rejected.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, BuildSpmDataExtendPermsLimit001, TestSize.Level0)
{
    HapTokenInfo hapInfo = BuildHapInfo(0x314, "bundle.one");
    BundleNoCachedInfo noCached = BuildNoCached();
    std::vector<BriefPermData> brief = BuildBriefList(1);
    std::vector<PermissionWithValue> extendPerms = {
        { "ohos.permission.INTERNET", std::string(5000, 'a') },
    };

    SpmDataPtr spmData = nullptr;
    // 4096: DEFAULT_EXTENDED_PERMS kernel read limit, buffer beyond it can never be loaded back
    EXPECT_EQ(ERR_OVERSIZE, KernelDetail::BuildSpmData(hapInfo, noCached, brief, extendPerms, spmData));
    EXPECT_EQ(nullptr, spmData.get());
}

/**
 * @tc.name: UpdateSpmDataTaskRollbackPermRetry001
 * @tc.desc: Verify perm rollback retries the failed restore once and succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTaskRollbackPermRetry001, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x317, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x318, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, &brief1, true },
        { hapInfo2, noCached2, brief2, extendPerms, &brief2, true },
    };
    // update: t1 ok, t2 fails and retry fails; rollback perm restore of t1 fails then retry succeeds
    GetFakeSpmKernelState().addPermRetSequence = { RET_SUCCESS, RET_FAILED, RET_FAILED, RET_FAILED, RET_SUCCESS };

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_FAILED, task.Update(errIndex));
    EXPECT_EQ(1u, errIndex);
    // spm entries restored by set, then perm restore of the first token retried once and succeeded
    EXPECT_EQ(5, GetFakeSpmKernelState().addPermCallCount);
    ASSERT_EQ(5u, GetFakeSpmKernelState().addPermTokenIds.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x317), GetFakeSpmKernelState().addPermTokenIds[3]);
    EXPECT_EQ(static_cast<AccessTokenID>(0x317), GetFakeSpmKernelState().addPermTokenIds[4]);
}

/**
 * @tc.name: UpdateSpmDataTaskRollbackPermRetryFail001
 * @tc.desc: Verify perm rollback failure after retry reports error.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, UpdateSpmDataTaskRollbackPermRetryFail001, TestSize.Level0)
{
    HapTokenInfo hapInfo1 = BuildHapInfo(0x319, "bundle.one");
    HapTokenInfo hapInfo2 = BuildHapInfo(0x320, "bundle.two");
    BundleNoCachedInfo noCached1 = BuildNoCached();
    BundleNoCachedInfo noCached2 = BuildNoCached();
    std::vector<BriefPermData> brief1 = BuildBriefList(1);
    std::vector<BriefPermData> brief2 = BuildBriefList(2);
    std::vector<PermissionWithValue> extendPerms;
    std::vector<SpmDataParam> params = {
        { hapInfo1, noCached1, brief1, extendPerms, &brief1, true },
        { hapInfo2, noCached2, brief2, extendPerms, &brief2, true },
    };
    // update succeeds, then explicit rollback fails perm restore of both tokens even after retry
    GetFakeSpmKernelState().addPermRetSequence = { RET_SUCCESS, RET_SUCCESS, RET_FAILED, RET_FAILED,
        RET_FAILED, RET_FAILED };

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(RET_SUCCESS, task.Update(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(RET_FAILED, task.Rollback());
    // update for both items, then both restores failed after inner retry (2 calls each)
    EXPECT_EQ(6, GetFakeSpmKernelState().addPermCallCount);
    ASSERT_EQ(6u, GetFakeSpmKernelState().addPermTokenIds.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x319), GetFakeSpmKernelState().addPermTokenIds[2]);
    EXPECT_EQ(static_cast<AccessTokenID>(0x319), GetFakeSpmKernelState().addPermTokenIds[3]);
    EXPECT_EQ(static_cast<AccessTokenID>(0x320), GetFakeSpmKernelState().addPermTokenIds[4]);
    EXPECT_EQ(static_cast<AccessTokenID>(0x320), GetFakeSpmKernelState().addPermTokenIds[5]);
}

/**
 * @tc.name: AddHapPermToKernelBrief001
 * @tc.desc: Verify AddHapPermToKernel(BriefPermData) forwards only granted opcodes in order.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddHapPermToKernelBrief001, TestSize.Level0)
{
    AccessTokenID tokenId = 0x330;
    BriefPermData granted1 = {0};
    granted1.permCode = 1;
    granted1.status = PERMISSION_GRANTED;
    BriefPermData denied = {0};
    denied.permCode = 2;
    denied.status = PERMISSION_DENIED;
    BriefPermData granted2 = {0};
    granted2.permCode = 3;
    granted2.status = PERMISSION_GRANTED;
    std::vector<BriefPermData> briefList = {granted1, denied, granted2};

    EXPECT_EQ(RET_SUCCESS, PermissionKernelUtils::AddHapPermToKernel(tokenId, briefList));
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount);
    ASSERT_EQ(1u, GetFakeSpmKernelState().addPermTokenIds.size());
    EXPECT_EQ(tokenId, GetFakeSpmKernelState().addPermTokenIds[0]);
    // only granted opcodes are forwarded and the original order is preserved
    ASSERT_EQ(1u, GetFakeSpmKernelState().addPermOpCodeBatches.size());
    ASSERT_EQ(2u, GetFakeSpmKernelState().addPermOpCodeBatches[0].size());
    EXPECT_EQ(1u, GetFakeSpmKernelState().addPermOpCodeBatches[0][0]);
    EXPECT_EQ(3u, GetFakeSpmKernelState().addPermOpCodeBatches[0][1]);
}

/**
 * @tc.name: AddHapPermToKernelBrief002
 * @tc.desc: Verify AddHapPermToKernel(BriefPermData) still touches kernel once for an empty list.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddHapPermToKernelBrief002, TestSize.Level0)
{
    AccessTokenID tokenId = 0x331;
    std::vector<BriefPermData> briefList;

    EXPECT_EQ(RET_SUCCESS, PermissionKernelUtils::AddHapPermToKernel(tokenId, briefList));
    // current contract: an empty brief list is still forwarded once with an empty opcode batch
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount);
    ASSERT_EQ(1u, GetFakeSpmKernelState().addPermOpCodeBatches.size());
    EXPECT_TRUE(GetFakeSpmKernelState().addPermOpCodeBatches[0].empty());
}

/**
 * @tc.name: AddHapPermToKernelBrief003
 * @tc.desc: Verify AddHapPermToKernel(BriefPermData) filters out a fully denied list.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddHapPermToKernelBrief003, TestSize.Level0)
{
    AccessTokenID tokenId = 0x332;
    BriefPermData denied1 = {0};
    denied1.permCode = 5;
    denied1.status = PERMISSION_DENIED;
    BriefPermData denied2 = {0};
    denied2.permCode = 6;
    denied2.status = PERMISSION_DENIED;
    std::vector<BriefPermData> briefList = {denied1, denied2};

    EXPECT_EQ(RET_SUCCESS, PermissionKernelUtils::AddHapPermToKernel(tokenId, briefList));
    EXPECT_EQ(1, GetFakeSpmKernelState().addPermCallCount);
    ASSERT_EQ(1u, GetFakeSpmKernelState().addPermOpCodeBatches.size());
    EXPECT_TRUE(GetFakeSpmKernelState().addPermOpCodeBatches[0].empty());
}

/**
 * @tc.name: AddHapPermToKernelBrief004
 * @tc.desc: Verify transient failure is retried once with the full granted opcode list.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddHapPermToKernelBrief004, TestSize.Level0)
{
    AccessTokenID tokenId = 0x333;
    std::vector<BriefPermData> briefList = BuildBriefList(7);
    // first call fails transiently, retry succeeds
    GetFakeSpmKernelState().addPermRetSequence = { RET_FAILED, RET_SUCCESS };

    EXPECT_EQ(RET_SUCCESS, PermissionKernelUtils::AddHapPermToKernel(tokenId, briefList));
    EXPECT_EQ(2, GetFakeSpmKernelState().addPermCallCount);
    // retry resubmits the full granted opcode list
    ASSERT_EQ(2u, GetFakeSpmKernelState().addPermOpCodeBatches.size());
    ASSERT_EQ(1u, GetFakeSpmKernelState().addPermOpCodeBatches[0].size());
    ASSERT_EQ(1u, GetFakeSpmKernelState().addPermOpCodeBatches[1].size());
    EXPECT_EQ(7u, GetFakeSpmKernelState().addPermOpCodeBatches[1][0]);
}

/**
 * @tc.name: AddHapPermToKernelBrief005
 * @tc.desc: Verify kernel error is propagated to the caller after the retry fails.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, AddHapPermToKernelBrief005, TestSize.Level0)
{
    AccessTokenID tokenId = 0x334;
    std::vector<BriefPermData> briefList = BuildBriefList(8);
    GetFakeSpmKernelState().addPermRetSequence = { RET_FAILED, RET_FAILED };

    // raw kernel error must propagate so perm-sync stage rollback can be triggered by the caller
    EXPECT_EQ(RET_FAILED, PermissionKernelUtils::AddHapPermToKernel(tokenId, briefList));
    EXPECT_EQ(2, GetFakeSpmKernelState().addPermCallCount);
    ASSERT_EQ(2u, GetFakeSpmKernelState().addPermTokenIds.size());
    EXPECT_EQ(tokenId, GetFakeSpmKernelState().addPermTokenIds[1]);
}

/**
 * @tc.name: RemoveSpmEntryFromKernelWrapper001
 * @tc.desc: Verify RemoveSpmEntryFromKernel wrapper success, benign codes and retry behavior.
 * @tc.type: FUNC
 */
HWTEST_F(SpmDataTaskTest, RemoveSpmEntryFromKernelWrapper001, TestSize.Level0)
{
    AccessTokenID tokenId = 0x335;

    // success path: kernel entry removed once and tokenId is passed through
    EXPECT_EQ(RET_SUCCESS, PermissionKernelUtils::RemoveSpmEntryFromKernel(tokenId));
    EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);
    ASSERT_EQ(1u, GetFakeSpmKernelState().removedTokenIds.size());
    EXPECT_EQ(tokenId, GetFakeSpmKernelState().removedTokenIds[0]);

    // benign: kernel reports ENOTSUP, removal is best-effort for rollback
    ResetFakeSpmKernelState();
    GetFakeSpmKernelState().removeRet = ENOTSUP;
    EXPECT_EQ(RET_SUCCESS, PermissionKernelUtils::RemoveSpmEntryFromKernel(tokenId));
    EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);

    // benign: entry absent (ENODATA), removal is idempotent
    ResetFakeSpmKernelState();
    GetFakeSpmKernelState().removeRet = ENODATA;
    EXPECT_EQ(RET_SUCCESS, PermissionKernelUtils::RemoveSpmEntryFromKernel(tokenId));
    EXPECT_EQ(1, GetFakeSpmKernelState().removeCallCount);

    // transient failure is retried once and succeeds
    ResetFakeSpmKernelState();
    GetFakeSpmKernelState().removeRetSequence = { RET_FAILED, RET_SUCCESS };
    EXPECT_EQ(RET_SUCCESS, PermissionKernelUtils::RemoveSpmEntryFromKernel(tokenId));
    EXPECT_EQ(2, GetFakeSpmKernelState().removeCallCount);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

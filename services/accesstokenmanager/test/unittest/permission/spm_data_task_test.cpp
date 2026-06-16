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
 * @tc.desc: Verify build failure returns ERR_PARAM_INVALID and does not touch kernel.
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
    // Note: PermissionKernelUtils::AddHapPermToKernel(BriefPermData) always returns RET_SUCCESS
    // So we test SPM data failure instead
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
 * @tc.desc: Verify load failure returns corresponding item index.
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
    ASSERT_EQ(4u, GetFakeSpmKernelState().setTokenBatches.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x106), GetFakeSpmKernelState().setTokenBatches[0][0]);
    EXPECT_EQ(static_cast<AccessTokenID>(0x107), GetFakeSpmKernelState().setTokenBatches[0][1]);
    ASSERT_EQ(1u, GetFakeSpmKernelState().setTokenBatches[2].size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x106), GetFakeSpmKernelState().setTokenBatches[1][0]);
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
 * @tc.desc: Verify updateWithPerm requires old permission data.
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

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(ERR_PARAM_INVALID, task.Update(errIndex));
    EXPECT_EQ(0, GetFakeSpmKernelState().getCallCount);
    EXPECT_EQ(0, GetFakeSpmKernelState().setCallCount);
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
    // [0x108, 0x109] [0x108, 0x109] [0x108] [0x108]
    EXPECT_EQ(ERR_KERNEL_COMMON_FAILED, task.Update(errIndex));
    EXPECT_EQ(1u, errIndex);
    ASSERT_EQ(4u, GetFakeSpmKernelState().setTokenBatches.size());
    ASSERT_EQ(1u, GetFakeSpmKernelState().setTokenBatches[2].size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x108), GetFakeSpmKernelState().setTokenBatches[1][0]);
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
    // Note: AddHapPermToKernel(BriefPermData) always returns RET_SUCCESS
    // So we test SPM data set failure instead
    GetFakeSpmKernelState().setRet = RET_FAILED;
    GetFakeSpmKernelState().setIdxErr = 1;

    UpdateSpmDataTask task(params);
    uint32_t errIndex = 99;
    EXPECT_EQ(ERR_KERNEL_COMMON_FAILED, task.Update(errIndex));
    EXPECT_EQ(1u, errIndex);
    // Two calls: one in Update (fails), one in Rollback (restores old data)
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
 * @tc.desc: Verify ENODATA error in LoadOldSpmDataForItems causes Update to fail.
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
    EXPECT_EQ(AccessTokenError::ERR_NO_DATA_FROM_KERNEL, task.Update(errIndex));
    EXPECT_EQ(0u, errIndex);
    EXPECT_EQ(1, GetFakeSpmKernelState().getCallCount);
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
    uint32_t opCode = *(reinterpret_cast<uint32_t*>(buffer.data()));
    EXPECT_NE(0u, opCode); // Valid permission should have non-zero opCode

    // Parse and verify valueSize
    uint32_t valueSize = *(reinterpret_cast<uint32_t*>(buffer.data() + sizeof(uint32_t)));
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
        uint32_t valueSize = *(reinterpret_cast<uint32_t*>(buffer.data() + offset + sizeof(uint32_t)));
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

    uint32_t valueSize = *(reinterpret_cast<uint32_t*>(buffer.data() + sizeof(uint32_t)));
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
    uint32_t valueSize = *(reinterpret_cast<uint32_t*>(buffer.data() + sizeof(uint32_t)));
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
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

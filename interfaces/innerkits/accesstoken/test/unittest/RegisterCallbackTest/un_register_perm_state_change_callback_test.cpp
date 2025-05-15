/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "un_register_perm_state_change_callback_test.h"
#include <thread>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "iaccess_token_manager.h"
#include "hap_token_info.h"
#include "nativetoken_kit.h"
#include "permission_grant_info.h"
#include "permission_state_change_info_parcel.h"
#include "string_ex.h"
#include "tokenid_kit.h"
#include "token_setproc.h"
#include "accesstoken_manager_client.h"
#include "test_common.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static MockHapToken* g_mock = nullptr;
uint64_t g_selfShellTokenId;
HapInfoParams g_infoManagerTestInfoParms = TestCommon::GetInfoManagerTestInfoParms();
}

void UnRegisterPermStateChangeCallbackTest::SetUpTestCase()
{
    g_selfShellTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfShellTokenId);
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    g_mock = new (std::nothrow) MockHapToken("UnRegisterPermStateChangeCallbackTest", reqPerm, true);
}

void UnRegisterPermStateChangeCallbackTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    SetSelfTokenID(g_selfShellTokenId);
    TestCommon::ResetTestEvironment();
}

void UnRegisterPermStateChangeCallbackTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
}

void UnRegisterPermStateChangeCallbackTest::TearDown()
{
}

class CbCustomizeTest : public PermStateChangeCallbackCustomize {
public:
    explicit CbCustomizeTest(const PermStateChangeScope &scopeInfo)
        : PermStateChangeCallbackCustomize(scopeInfo)
    {
    }

    ~CbCustomizeTest()
    {}

    virtual void PermStateChangeCallback(PermStateChangeInfo& result)
    {
        ready_ = true;
        int32_t status = (result.permStateChangeType == 1) ? PERMISSION_GRANTED : PERMISSION_DENIED;
        ASSERT_EQ(status, AccessTokenKit::VerifyAccessToken(result.tokenID, result.permissionName));
    }

    bool ready_;
};

/**
 * @tc.name: UnRegisterPermStateChangeCallbackAbnormalTest001
 * @tc.desc: UnRegisterPermStateChangeCallback with invalid input.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(UnRegisterPermStateChangeCallbackTest, UnRegisterPermStateChangeCallbackAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UnRegisterPermStateChangeCallbackAbnormalTest001");
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(AccessTokenError::ERR_INTERFACE_NOT_USED_TOGETHER, res);
}

/**
 * @tc.name: UnRegisterPermStateChangeCallbackSpecTest001
 * @tc.desc: UnRegisterPermStateChangeCallback repeatedly.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(UnRegisterPermStateChangeCallbackTest, UnRegisterPermStateChangeCallbackSpecTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UnRegisterPermStateChangeCallbackSpecTest001");
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(AccessTokenError::ERR_CALLBACK_ALREADY_EXIST, res);
    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(AccessTokenError::ERR_INTERFACE_NOT_USED_TOGETHER, res);
}

/**
 * @tc.name: UnRegisterPermStateChangeCallbackFuncTest001
 * @tc.desc: UnRegisterPermStateChangeCallback caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(UnRegisterPermStateChangeCallbackTest, UnRegisterPermStateChangeCallbackFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UnRegisterPermStateChangeCallbackFuncTest001");
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
        MockHapToken mock("UnRegisterPermStateChangeCallbackFuncTest001", reqPerm, false);

        res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
        ASSERT_EQ(ERR_NOT_SYSTEM_APP, res);
    }

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: UnRegisterSelfPermStateChangeCallback001
 * @tc.desc: UnRegisterSelfPermStateChangeCallback with invalid input.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(UnRegisterPermStateChangeCallbackTest, UnRegisterSelfPermStateChangeCallback001, TestSize.Level0)
{
    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(AccessTokenError::ERR_INTERFACE_NOT_USED_TOGETHER, res);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
    SetSelfTokenID(g_selfShellTokenId);
}

/**
 * @tc.name: UnRegisterSelfPermStateChangeCallback002
 * @tc.desc: UnRegisterSelfPermStateChangeCallback repeatedly.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(UnRegisterPermStateChangeCallbackTest, UnRegisterSelfPermStateChangeCallback002, TestSize.Level0)
{
    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);
    res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(AccessTokenError::ERR_CALLBACK_ALREADY_EXIST, res);
    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);
    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(AccessTokenError::ERR_INTERFACE_NOT_USED_TOGETHER, res);
    SetSelfTokenID(g_selfShellTokenId);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: UnRegisterSelfPermStateChangeCallback003
 * @tc.desc: UnRegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(UnRegisterPermStateChangeCallbackTest, UnRegisterSelfPermStateChangeCallback003, TestSize.Level0)
{
    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(g_selfShellTokenId);

    callbackPtr->ready_ = false;

    res = TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    res = TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: UnRegisterSelfPermStateChangeCallback004
 * @tc.desc: UnRegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(UnRegisterPermStateChangeCallbackTest, UnRegisterSelfPermStateChangeCallback004, TestSize.Level0)
{
    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static PermissionStateFull infoManagerTestStateB = {
        .permissionName = "ohos.permission.GET_BUNDLE_INFO",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {infoManagerTestStateA, infoManagerTestStateB}
    };
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(g_selfShellTokenId);

    callbackPtr->ready_ = false;

    res = TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    res = TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: UnRegisterSelfPermStateChangeCallback005
 * @tc.desc: UnRegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(UnRegisterPermStateChangeCallbackTest, UnRegisterSelfPermStateChangeCallback005, TestSize.Level0)
{
    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(g_selfShellTokenId);

    SetSelfTokenID(tokenID);
    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(g_selfShellTokenId);

    callbackPtr->ready_ = false;

    res = TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    res = TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: UnRegisterSelfPermStateChangeCallback006
 * @tc.desc: UnRegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(UnRegisterPermStateChangeCallbackTest, UnRegisterSelfPermStateChangeCallback006, TestSize.Level0)
{
    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static PermissionStateFull infoManagerTestStateB = {
        .permissionName = "ohos.permission.DISTRIBUTED_DATASYNC",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {infoManagerTestStateA, infoManagerTestStateB}
    };
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA", "ohos.permission.DISTRIBUTED_DATASYNC"};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr));
    SetSelfTokenID(g_selfShellTokenId);

    callbackPtr->ready_ = false;

    EXPECT_EQ(RET_SUCCESS, TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.CAMERA", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    EXPECT_EQ(RET_SUCCESS, TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.CAMERA", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    EXPECT_EQ(RET_SUCCESS, TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.DISTRIBUTED_DATASYNC", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    EXPECT_EQ(RET_SUCCESS, TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.DISTRIBUTED_DATASYNC", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: UnRegisterSelfPermStateChangeCallback007
 * @tc.desc: UnRegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(UnRegisterPermStateChangeCallbackTest, UnRegisterSelfPermStateChangeCallback007, TestSize.Level0)
{
    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.INVALID", "ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(g_selfShellTokenId);

    callbackPtr->ready_ = false;

    res = TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    res = TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
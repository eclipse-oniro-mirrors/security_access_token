/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "register_perm_state_change_callback_test.h"
#include <thread>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_service_ipc_interface_code.h"
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
HapInfoParams g_infoManagerTestInfoParms = TestCommon::GetInfoManagerTestInfoParms();
uint64_t g_selfShellTokenId;
static const uint32_t TOKENIDS_LIST_SIZE_MAX_TEST = 1024;
static const uint32_t PERMS_LIST_SIZE_MAX_TEST = 1024;
static const uint32_t MAX_CALLBACK_MAP_SIZE = 200;
PermissionStateFull g_infoManagerTestStateA = {
    .permissionName = "ohos.permission.CAMERA",
    .isGeneral = true,
    .resDeviceID = {"local2"},
    .grantStatus = {PERMISSION_DENIED},
    .grantFlags = {1}
};
}

void RegisterPermStateChangeCallbackTest::SetUpTestCase()
{
    g_selfShellTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfShellTokenId);
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    g_mock = new (std::nothrow) MockHapToken("RegisterPermStateChangeCallbackTest", reqPerm, true);
}

void RegisterPermStateChangeCallbackTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    EXPECT_EQ(0, SetSelfTokenID(g_selfShellTokenId));
    TestCommon::ResetTestEvironment();
}

void RegisterPermStateChangeCallbackTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
}

void RegisterPermStateChangeCallbackTest::TearDown()
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
 * @tc.name: RegisterPermStateChangeCallbackFuncTest001
 * @tc.desc: RegisterPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterPermStateChangeCallbackFuncTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterPermStateChangeCallbackFuncTest001");
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));

    static HapPolicyParams infoManagerTestPolicyPrams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {g_infoManagerTestStateA}
    };

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(
        RET_SUCCESS, TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(tokenID, INVALID_TOKENID);

    EXPECT_EQ(RET_SUCCESS, TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.CAMERA", 2));

    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    EXPECT_EQ(RET_SUCCESS, TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.CAMERA", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr));

    callbackPtr->ready_ = false;

    EXPECT_EQ(RET_SUCCESS, TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.CAMERA", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    EXPECT_EQ(RET_SUCCESS, TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.CAMERA", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RegisterPermStateChangeCallbackFuncTest002
 * @tc.desc: RegisterPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterPermStateChangeCallbackFuncTest002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterPermStateChangeCallbackFuncTest002");
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.APPROXIMATELY_LOCATION"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);

    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_GRANTED},
        .grantFlags = {1}
    };
    static PermissionStateFull infoManagerTestStateB = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_GRANTED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams2 = {
        .apl = APL_SYSTEM_BASIC,
        .domain = "test.domain2",
        .permStateList = {infoManagerTestStateA, infoManagerTestStateB}
    };

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(
        RET_SUCCESS, TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams2, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(tokenID, INVALID_TOKENID);

    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false);
    EXPECT_EQ(PERMISSION_DENIED, res);

    res = TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallbackFuncTest003
 * @tc.desc: RegisterPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterPermStateChangeCallbackFuncTest003, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterPermStateChangeCallbackFuncTest003");
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));

    HapPolicyParams infoManagerTestPolicyPrams3 = {
        .apl = APL_SYSTEM_CORE,
        .domain = "test.domain2",
        .permStateList = {g_infoManagerTestStateA}
    };

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(
        RET_SUCCESS, TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams3, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(tokenID, INVALID_TOKENID);

    callbackPtr->ready_ = false;
    EXPECT_EQ(RET_SUCCESS, TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.CAMERA", 2));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr));
}

/**
 * @tc.name: RegisterPermStateChangeCallbackFuncTest004
 * @tc.desc: RegisterPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterPermStateChangeCallbackFuncTest004, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterPermStateChangeCallbackFuncTest004");

    static HapPolicyParams infoManagerTestPolicyPrams5 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {g_infoManagerTestStateA}
    };

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(
        RET_SUCCESS, TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams5, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(tokenID, INVALID_TOKENID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {tokenID, 0};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));

    callbackPtr->ready_ = false;
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false));
    EXPECT_EQ(RET_SUCCESS, TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.CAMERA", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr));
}


/**
 * @tc.name: RegisterPermStateChangeCallbackFuncTest005
 * @tc.desc: RegisterPermStateChangeCallback caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterPermStateChangeCallbackFuncTest005, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterPermStateChangeCallbackFuncTest005");
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    MockHapToken mock("RegisterPermStateChangeCallbackFuncTest005", reqPerm, false);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    ASSERT_EQ(ERR_NOT_SYSTEM_APP, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));
}

/**
 * @tc.name: RegisterPermStateChangeCallbackFuncTest006
 * @tc.desc: RegisterPermStateChangeCallback caller is system app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterPermStateChangeCallbackFuncTest006, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterPermStateChangeCallbackFuncTest006");
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    MockHapToken mock("RegisterPermStateChangeCallbackFuncTest006", reqPerm, true);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr));
}

/**
 * @tc.name: RegisterPermStateChangeCallbackAbnormalTest001
 * @tc.desc: RegisterPermStateChangeCallback with invalid tokenId
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterPermStateChangeCallbackAbnormalTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterPermStateChangeCallbackAbnormalTest001");
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {555555}; // 555555为模拟的tokenid
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));

    PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_GRANTED},
        .grantFlags = {1}
    };
    HapPolicyParams infoManagerTestPolicyPrams4 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {infoManagerTestStateA}
    };

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(
        RET_SUCCESS, TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams4, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(tokenID, INVALID_TOKENID);

    callbackPtr->ready_ = false;
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false));
    EXPECT_EQ(RET_SUCCESS, TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.CAMERA", 2));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RegisterPermStateChangeCallbackAbnormalTest002
 * @tc.desc: RegisterPermStateChangeCallback with invaild permission
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterPermStateChangeCallbackAbnormalTest002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterPermStateChangeCallbackAbnormalTest002");
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.INVALID"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr1 = std::make_shared<CbCustomizeTest>(scopeInfo);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr1));

    static PermissionStateFull infoManagerTestState = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams6 = {
        .apl = APL_SYSTEM_BASIC,
        .domain = "test.domain2",
        .permStateList = {infoManagerTestState}
    };

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(
        RET_SUCCESS, TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams6, tokenIdEx));
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);

    scopeInfo.tokenIDs = {tokenIdEx.tokenIdExStruct.tokenID};
    scopeInfo.permList = {"ohos.permission.INVALID", "ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));

    int32_t res = TestCommon::GrantPermissionByTest(tokenIdEx.tokenIdExStruct.tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID));

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallbackAbnormalTest003
 * @tc.desc: RegisterPermStateChangeCallback with nullptr
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterPermStateChangeCallbackAbnormalTest003, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterPermStateChangeCallbackAbnormalTest003");
    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(nullptr);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);
}

/**
 * @tc.name: RegisterPermStateChangeCallbackSpecTest001
 * @tc.desc: RegisterPermStateChangeCallback with permList, whose size is PERMS_LIST_SIZE_MAX_TEST
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterPermStateChangeCallbackSpecTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterPermStateChangeCallbackSpecTest001");
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {};
    for (int32_t i = 0; i <= PERMS_LIST_SIZE_MAX_TEST; i++) {
        scopeInfo.permList.emplace_back("ohos.permission.APPROXIMATELY_LOCATION");
        if (i == PERMS_LIST_SIZE_MAX_TEST) {
            auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
            ASSERT_EQ(
                AccessTokenError::ERR_PARAM_INVALID,  AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));
            break;
        }
        auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));
        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr));
    }
}

/**
 * @tc.name: RegisterPermStateChangeCallbackSpecTest002
 * @tc.desc: RegisterPermStateChangeCallback with tokenList, whose token size is oversize
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterPermStateChangeCallbackSpecTest002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterPermStateChangeCallbackSpecTest002");
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    static HapPolicyParams infoManagerTestPolicyPrams8 = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permStateList = {}
    };

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(
        RET_SUCCESS, TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams8, tokenIdEx));
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);

    for (int32_t i = 0; i <= TOKENIDS_LIST_SIZE_MAX_TEST; i++) {
        scopeInfo.tokenIDs.emplace_back(tokenIdEx.tokenIdExStruct.tokenID);
        if (i == TOKENIDS_LIST_SIZE_MAX_TEST) {
            auto callbackPtr1 = std::make_shared<CbCustomizeTest>(scopeInfo);
            EXPECT_EQ(
                AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr1));
            break;
        }
        auto callbackPtr1 = std::make_shared<CbCustomizeTest>(scopeInfo);
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr1));
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr1));
    }

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: RegisterPermStateChangeCallbackSpecTest003
 * @tc.desc: RegisterPermStateChangeCallback
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterPermStateChangeCallbackSpecTest003, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterPermStateChangeCallbackSpecTest003");
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {};
    std::vector<std::shared_ptr<CbCustomizeTest>> callbackList;

    for (int32_t i = 0; i < MAX_CALLBACK_MAP_SIZE; i++) { // 200 is the max size
        if (i == MAX_CALLBACK_MAP_SIZE) { // 200 is the max size
            auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
            ASSERT_EQ(AccessTokenError::ERR_CALLBACKS_EXCEED_LIMITATION,
                AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));
            break;
        }
        auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));
        callbackList.emplace_back(callbackPtr);
    }
    for (int32_t i = 0; i < MAX_CALLBACK_MAP_SIZE; i++) { // release 200 callback
        auto callbackPtr = callbackList[i];
        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr));
    }
    callbackList.clear();
}

/**
 * @tc.name: RegisterPermStateChangeCallbackSpecTest004
 * @tc.desc: ClearUserGrantedPermissionState notify.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterPermStateChangeCallbackSpecTest004, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterPermStateChangeCallbackSpecTest004");
    PermStateChangeScope scopeInfo;

    static HapPolicyParams infoManagerTestPolicyPrams13 = {
        .apl = APL_SYSTEM_BASIC,
        .domain = "test.domain2",
        .permStateList = {g_infoManagerTestStateA}
    };

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams13, tokenIdEx));
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);

    scopeInfo.tokenIDs = {tokenIdEx.tokenIdExStruct.tokenID};
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);

    res = TestCommon::GrantPermissionByTest(tokenIdEx.tokenIdExStruct.tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
        MockHapToken mock("RegisterPermStateChangeCallbackSpecTest004", reqPerm);
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserGrantedPermissionState(tokenIdEx.tokenIdExStruct.tokenID));
    }
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = TestCommon::GrantPermissionByTest(tokenIdEx.tokenIdExStruct.tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr));
}

/**
 * @tc.name: RegisterPermStateChangeCallbackSpecTest005
 * @tc.desc: ClearUserGrantedPermissionState notify.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterPermStateChangeCallbackSpecTest005, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterPermStateChangeCallbackSpecTest005");
    PermStateChangeScope scopeInfo;
    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.READ_MEDIA",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams14 = {
        .apl = APL_SYSTEM_BASIC,
        .domain = "testA.domain2",
        .permStateList = {infoManagerTestStateA}
    };

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams14, tokenIdEx));
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);

    scopeInfo.tokenIDs = {tokenIdEx.tokenIdExStruct.tokenID};
    scopeInfo.permList = {"ohos.permission.READ_MEDIA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);

    res = TestCommon::GrantPermissionByTest(tokenIdEx.tokenIdExStruct.tokenID,
        "ohos.permission.READ_MEDIA", PERMISSION_SYSTEM_FIXED);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
        MockHapToken mock("RegisterPermStateChangeCallbackSpecTest004", reqPerm);
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserGrantedPermissionState(tokenIdEx.tokenIdExStruct.tokenID));
    }
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback001
 * @tc.desc: RegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterSelfPermStateChangeCallback001, TestSize.Level1)
{
    static HapPolicyParams infoManagerTestPolicyPrams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {g_infoManagerTestStateA}
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
    SetSelfTokenID(g_selfShellTokenId);

    res = TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false);
    EXPECT_EQ(PERMISSION_GRANTED, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    res = TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    SetSelfTokenID(tokenID);
    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(g_selfShellTokenId);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback002
 * @tc.desc: RegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterSelfPermStateChangeCallback002, TestSize.Level1)
{
    static HapPolicyParams infoManagerTestPolicyPrams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {g_infoManagerTestStateA}
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
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr));
    SetSelfTokenID(g_selfShellTokenId);

    EXPECT_EQ(RET_SUCCESS, TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.CAMERA", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    EXPECT_EQ(RET_SUCCESS, TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.CAMERA", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr));
    SetSelfTokenID(g_selfShellTokenId);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback003
 * @tc.desc: RegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterSelfPermStateChangeCallback003, TestSize.Level1)
{
    static HapPolicyParams infoManagerTestPolicyPrams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {g_infoManagerTestStateA}
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

    res = TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false);
    EXPECT_EQ(PERMISSION_GRANTED, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    res = TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    SetSelfTokenID(tokenID);
    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(g_selfShellTokenId);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback004
 * @tc.desc: RegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterSelfPermStateChangeCallback004, TestSize.Level1)
{
    PermissionStateFull infoManagerTestStateB = {
        .permissionName = "ohos.permission.MICROPHONE",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    HapPolicyParams infoManagerTestPolicyPrams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {g_infoManagerTestStateA, infoManagerTestStateB}
    };
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA", "ohos.permission.MICROPHONE"};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr));
    SetSelfTokenID(g_selfShellTokenId);

    EXPECT_EQ(RET_SUCCESS, TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.CAMERA", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    EXPECT_EQ(RET_SUCCESS, TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.CAMERA", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    EXPECT_EQ(RET_SUCCESS, TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.MICROPHONE", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    EXPECT_EQ(RET_SUCCESS, TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.MICROPHONE", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    SetSelfTokenID(tokenID);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr));
    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback005
 * @tc.desc: RegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterSelfPermStateChangeCallback005, TestSize.Level1)
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
        .permStateList = {g_infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.INVALID"};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr1 = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr1->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr1);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);

    scopeInfo.permList = {"ohos.permission.INVALID", "ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(g_selfShellTokenId);

    res = TestCommon::GrantPermissionByTest(tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false);
    EXPECT_EQ(PERMISSION_GRANTED, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    res = TestCommon::RevokePermissionByTest(tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    SetSelfTokenID(tokenID);
    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, res);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback006
 * @tc.desc: RegisterSelfPermStateChangeCallback with permList, whose size is oversize
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterSelfPermStateChangeCallback006, TestSize.Level1)
{
    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.GET_BUNDLE_INFO",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    SetSelfTokenID(tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {GetSelfTokenID()};
    for (int32_t i = 0; i <= PERMS_LIST_SIZE_MAX_TEST; i++) { // 1025 is a invalid size
        scopeInfo.permList.emplace_back("ohos.permission.MICROPHONE");
        if (i == PERMS_LIST_SIZE_MAX_TEST) { // 1025 is a invalid size
            auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
            int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
            EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);
            break;
        }
        auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr));
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr));
    }
    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback007
 * @tc.desc: RegisterSelfPermStateChangeCallback without set TokenID.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterSelfPermStateChangeCallback007, TestSize.Level1)
{
    static HapPolicyParams infoManagerTestPolicyPrams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permList = {},
        .permStateList = {g_infoManagerTestStateA}
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

    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback008
 * @tc.desc: RegisterSelfPermStateChangeCallback with none or two tokenIDs.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterSelfPermStateChangeCallback008, TestSize.Level1)
{
    static HapPolicyParams infoManagerTestPolicyPrams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permStateList = {g_infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    HapInfoParams infoManagerTestInfoParms2 = {
        .userID = 1,
        .bundleName = "accesstoken_test_2",
        .instIndex = 0,
        .appIDDesc = "test2",
        .apiVersion = TestCommon::DEFAULT_API_VERSION
    };

    ASSERT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(infoManagerTestInfoParms2, infoManagerTestPolicyPrams1, tokenIdEx));
    AccessTokenID tokenID2 = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID2);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr1 = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr1->ready_ = false;

    // tokenIDs size si 0,
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr1);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);

    scopeInfo.tokenIDs = {tokenID, tokenID2};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    // tokenIDs size != 1
    res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);

    SetSelfTokenID(g_selfShellTokenId);
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID2));
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback009
 * @tc.desc: RegisterSelfPermStateChangeCallback
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterSelfPermStateChangeCallback009, TestSize.Level1)
{
    static HapPolicyParams infoManagerTestPolicyPrams1 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permList = {},
        .permStateList = {g_infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    SetSelfTokenID(tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {tokenID};
    std::vector<std::shared_ptr<CbCustomizeTest>> callbackList;

    for (int32_t i = 0; i < MAX_CALLBACK_MAP_SIZE; i++) { // 200 is the max size
        if (i == MAX_CALLBACK_MAP_SIZE) { // 200 is the max size
            auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
            int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
            EXPECT_EQ(AccessTokenError::ERR_CALLBACKS_EXCEED_LIMITATION, res);
            break;
        }
        auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr));
        callbackList.emplace_back(callbackPtr);
    }
    for (int32_t i = 0; i < MAX_CALLBACK_MAP_SIZE; i++) { // release 200 callback
        auto callbackPtr = callbackList[i];
        int32_t res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
        ASSERT_EQ(RET_SUCCESS, res);
    }
    callbackList.clear();

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback010
 * @tc.desc: RegisterSelfPermStateChangeCallback with nullptr
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterSelfPermStateChangeCallback010, TestSize.Level1)
{
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(nullptr);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

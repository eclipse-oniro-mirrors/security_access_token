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
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int TEST_USER_ID = 0;

HapInfoParams g_locationTestInfo = {
    .userID = TEST_USER_ID,
    .bundleName = "accesstoken_location_test",
    .instIndex = 0,
    .appIDDesc = "test2"
};

HapInfoParams g_infoManagerTestNormalInfoParms = TestCommon::GetInfoManagerTestNormalInfoParms();
HapInfoParams g_infoManagerTestSystemInfoParms = TestCommon::GetInfoManagerTestSystemInfoParms();
HapInfoParams g_infoManagerTestInfoParms = TestCommon::GetInfoManagerTestInfoParms();
HapPolicyParams g_infoManagerTestPolicyPrams = TestCommon::GetInfoManagerTestPolicyPrams();

HapInfoParams g_infoManagerTestInfoParmsBak = g_infoManagerTestInfoParms;
HapPolicyParams g_infoManagerTestPolicyPramsBak = g_infoManagerTestPolicyPrams;

uint64_t g_selfShellTokenId;
}

void RegisterPermStateChangeCallbackTest::SetUpTestCase()
{
    g_selfShellTokenId = GetSelfTokenID();
    // clean up test cases
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenId);

    tokenId = AccessTokenKit::GetHapTokenID(g_infoManagerTestNormalInfoParms.userID,
                                            g_infoManagerTestNormalInfoParms.bundleName,
                                            g_infoManagerTestNormalInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenId);

    tokenId = AccessTokenKit::GetHapTokenID(g_infoManagerTestSystemInfoParms.userID,
                                            g_infoManagerTestSystemInfoParms.bundleName,
                                            g_infoManagerTestSystemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenId);

    tokenId = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenId);

    TestCommon::GetNativeTokenTest();
}

void RegisterPermStateChangeCallbackTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfShellTokenId);
}

void RegisterPermStateChangeCallbackTest::SetUp()
{
    setuid(0);
    selfTokenId_ = GetSelfTokenID();
    g_infoManagerTestInfoParms = g_infoManagerTestInfoParmsBak;
    g_infoManagerTestPolicyPrams = g_infoManagerTestPolicyPramsBak;
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "appIDDesc",
        .apiVersion = 8,
        .isSystemApp = true
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    AccessTokenKit::AllocHapToken(info, policy);
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
}

void RegisterPermStateChangeCallbackTest::TearDown()
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenId);
    tokenId = AccessTokenKit::GetHapTokenID(g_infoManagerTestNormalInfoParms.userID,
                                            g_infoManagerTestNormalInfoParms.bundleName,
                                            g_infoManagerTestNormalInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenId);

    tokenId = AccessTokenKit::GetHapTokenID(g_infoManagerTestSystemInfoParms.userID,
                                            g_infoManagerTestSystemInfoParms.bundleName,
                                            g_infoManagerTestSystemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenId);
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

void RegisterPermStateChangeCallbackTest::AllocHapToken(std::vector<PermissionDef>& permissionDefs,
    std::vector<PermissionStateFull>& permissionStateFulls, int32_t apiVersion)
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, "accesstoken_location_test", 0);
    AccessTokenKit::DeleteToken(tokenID);

    HapInfoParams info = g_locationTestInfo;
    info.apiVersion = apiVersion;

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };

    for (auto& permissionDef:permissionDefs) {
        policy.permList.emplace_back(permissionDef);
    }

    for (auto& permissionStateFull:permissionStateFulls) {
        policy.permStateList.emplace_back(permissionStateFull);
    }

    AccessTokenKit::AllocHapToken(info, policy);
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

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

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
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };

    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(PERMISSION_GRANTED, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    res = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    callbackPtr->ready_ = false;

    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(false, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    res = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(false, callbackPtr->ready_);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
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
    scopeInfo.permList = {"ohos.permission.GET_BUNDLE_INFO"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);

    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.GET_BUNDLE_INFO",
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
        .permList = {},
        .permStateList = {infoManagerTestStateA, infoManagerTestStateB}
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams2);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(PERMISSION_GRANTED, res);

    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
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

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);

    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.GET_BUNDLE_INFO",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static PermissionStateFull infoManagerTestStateB = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams3 = {
        .apl = APL_SYSTEM_CORE,
        .domain = "test.domain2",
        .permList = {},
        .permStateList = {infoManagerTestStateA, infoManagerTestStateB}
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams3);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    callbackPtr->ready_ = false;
    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(PERMISSION_GRANTED, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.GET_BUNDLE_INFO", false);
    ASSERT_EQ(PERMISSION_DENIED, res);
    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.GET_BUNDLE_INFO", 2);
    ASSERT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
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
        .grantStatus = {PERMISSION_GRANTED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams5 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permList = {},
        .permStateList = {infoManagerTestStateA, infoManagerTestStateB}
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams5);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.GET_BUNDLE_INFO", "ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {tokenID, 0};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(PERMISSION_DENIED, res);
    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.CAMERA", 2);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(RET_SUCCESS, res);
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.GET_BUNDLE_INFO", false);
    ASSERT_EQ(PERMISSION_GRANTED, res);
    res = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.GET_BUNDLE_INFO", 2);
    ASSERT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
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
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestNormalInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(ERR_NOT_SYSTEM_APP, res);
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
    static HapPolicyParams policyPrams = {
        .apl = APL_SYSTEM_CORE,
        .domain = "test.domain",
    };
    PermissionStateFull g_getPermissionReq = {
        .permissionName = "ohos.permission.GET_SENSITIVE_PERMISSIONS",
        .isGeneral = true,
        .resDeviceID = {"device2"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
    };
    policyPrams.permStateList.emplace_back(g_getPermissionReq);
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms, policyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
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
    scopeInfo.permList = {"ohos.permission.GET_BUNDLE_INFO", "ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {555555}; // 555555为模拟的tokenid
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);

    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.GET_BUNDLE_INFO",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_GRANTED},
        .grantFlags = {1},
    };
    static PermissionStateFull infoManagerTestStateB = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_GRANTED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams4 = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permList = {},
        .permStateList = {infoManagerTestStateA, infoManagerTestStateB}
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams4);

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    callbackPtr->ready_ = false;
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(PERMISSION_GRANTED, res);
    res = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(PERMISSION_DENIED, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.GET_BUNDLE_INFO", false);
    ASSERT_EQ(PERMISSION_GRANTED, res);
    res = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.GET_BUNDLE_INFO", 2);
    ASSERT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
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
    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr1);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);

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
        .permList = {},
        .permStateList = {infoManagerTestState}
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams6);

    scopeInfo.tokenIDs = {tokenIdEx.tokenIdExStruct.tokenID};
    scopeInfo.permList = {"ohos.permission.INVALID", "ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::GrantPermission(tokenIdEx.tokenIdExStruct.tokenID, "ohos.permission.CAMERA", 2);
    ASSERT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    res = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
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
 * @tc.desc: RegisterPermStateChangeCallback with permList, whose size is 1024/1025
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(RegisterPermStateChangeCallbackTest, RegisterPermStateChangeCallbackSpecTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RegisterPermStateChangeCallbackSpecTest001");
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {};
    for (int32_t i = 1; i <= 1025; i++) { // 1025 is a invalid size
        scopeInfo.permList.emplace_back("ohos.permission.GET_BUNDLE_INFO");
        if (i == 1025) { // 1025 is a invalid size
            auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
            int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
            ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);
            break;
        }
        auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
        int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
        ASSERT_EQ(RET_SUCCESS, res);
        res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
        ASSERT_EQ(RET_SUCCESS, res);
    }
}

/**
 * @tc.name: RegisterPermStateChangeCallbackSpecTest002
 * @tc.desc: RegisterPermStateChangeCallback with tokenList, whose size is 1024/1025
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
        .permList = {},
        .permStateList = {}
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams8);

    for (int32_t i = 1; i <= 1025; i++) { // 1025 is a invalid size
        scopeInfo.tokenIDs.emplace_back(tokenIdEx.tokenIdExStruct.tokenID);
        if (i == 1025) { // 1025 is a invalid size
            auto callbackPtr1 = std::make_shared<CbCustomizeTest>(scopeInfo);
            int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr1);
            ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);
            break;
        }
        auto callbackPtr1 = std::make_shared<CbCustomizeTest>(scopeInfo);
        int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr1);
        ASSERT_EQ(RET_SUCCESS, res);
        res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr1);
        ASSERT_EQ(RET_SUCCESS, res);
    }

    int32_t res = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
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

    for (int32_t i = 0; i < 200; i++) { // 200 is the max size
        if (i == 200) { // 200 is the max size
            auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
            int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
            ASSERT_EQ(AccessTokenError::ERR_CALLBACKS_EXCEED_LIMITATION, res);
            break;
        }
        auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
        int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
        ASSERT_EQ(RET_SUCCESS, res);
        callbackList.emplace_back(callbackPtr);
    }
    for (int32_t i = 0; i < 200; i++) { // release 200 callback
        auto callbackPtr = callbackList[i];
        int32_t res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
        ASSERT_EQ(RET_SUCCESS, res);
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
    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PERMISSION_DENIED},
        .grantFlags = {1}
    };
    static HapPolicyParams infoManagerTestPolicyPrams13 = {
        .apl = APL_SYSTEM_BASIC,
        .domain = "test.domain2",
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams13);

    scopeInfo.tokenIDs = {tokenIdEx.tokenIdExStruct.tokenID};
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::GrantPermission(tokenIdEx.tokenIdExStruct.tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::ClearUserGrantedPermissionState(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::GrantPermission(tokenIdEx.tokenIdExStruct.tokenID, "ohos.permission.CAMERA", 2);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
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
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams14);

    scopeInfo.tokenIDs = {tokenIdEx.tokenIdExStruct.tokenID};
    scopeInfo.permList = {"ohos.permission.READ_MEDIA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::GrantPermission(tokenIdEx.tokenIdExStruct.tokenID,
        "ohos.permission.READ_MEDIA", PERMISSION_SYSTEM_FIXED);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::ClearUserGrantedPermissionState(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    callbackPtr->ready_ = false;
    res = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, res);
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

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

#include "accesstoken_kit_extension_test.h"
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
#define private public
#include "accesstoken_manager_client.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t DEFAULT_API_VERSION = 8;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const std::string TEST_PERMISSION_NAME_ALPHA = "ohos.permission.ALPHA";
static const std::string TEST_PERMISSION_NAME_BETA = "ohos.permission.BETA";
static const int TEST_USER_ID = 0;

PermissionStateFull g_getPermissionReq = {
    .permissionName = "ohos.permission.GET_SENSITIVE_PERMISSIONS",
    .isGeneral = true,
    .resDeviceID = {"device2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};

PermissionStateFull g_revokePermissionReq = {
    .permissionName = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS",
    .isGeneral = true,
    .resDeviceID = {"device2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};

PermissionStateFull g_grantPermissionReq = {
    .permissionName = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS",
    .isGeneral = true,
    .resDeviceID = {"device2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};

PermissionDef g_infoManagerTestPermDef1 = {
    .permissionName = "ohos.permission.test1",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label2",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1
};

PermissionDef g_infoManagerTestPermDef2 = {
    .permissionName = "ohos.permission.test2",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label2",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1
};

PermissionDef g_infoManagerTestPermDef3 = {
    .permissionName = "ohos.permission.GET_BUNDLE_INFO_TEST",
    .bundleName = "accesstoken_test3",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label3",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1
};

PermissionStateFull g_infoManagerTestState1 = {
    .permissionName = "ohos.permission.test1",
    .isGeneral = true,
    .resDeviceID = {"local2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

PermissionStateFull g_infoManagerTestState2 = {
    .permissionName = "ohos.permission.test2",
    .isGeneral = false,
    .resDeviceID = {"device 1", "device 2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED, PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1, 2}
};

PermissionStateFull g_infoManagerTestState3 = {
    .permissionName = "ohos.permission.GET_BUNDLE_INFO",
    .isGeneral = true,
    .resDeviceID = {"local3"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

HapInfoParams g_infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "test2",
    .apiVersion = DEFAULT_API_VERSION
};

HapPolicyParams g_infoManagerTestPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain2",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};

HapInfoParams g_infoManagerTestInfoParmsBak = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "test2",
    .apiVersion = DEFAULT_API_VERSION
};

HapPolicyParams g_infoManagerTestPolicyPramsBak = {
    .apl = APL_NORMAL,
    .domain = "test.domain2",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};

HapInfoParams g_locationTestInfo = {
    .userID = TEST_USER_ID,
    .bundleName = "accesstoken_location_test",
    .instIndex = 0,
    .appIDDesc = "test2"
};

PermissionDef g_locationTestDefVague = {
    .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
    .bundleName = "accesstoken_location_test",
    .grantMode = GrantMode::USER_GRANT,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = true
};

PermissionDef g_locationTestDefAccurate = {
    .permissionName = "ohos.permission.LOCATION",
    .bundleName = "accesstoken_location_test",
    .grantMode = GrantMode::USER_GRANT,
    .availableLevel = APL_NORMAL,
    .provisionEnable = true,
    .distributedSceneEnable = true
};

PermissionDef g_locationTestDefSystemGrant = {
    .permissionName = "ohos.permission.locationtest1",
    .bundleName = "accesstoken_location_test",
    .grantMode = GrantMode::SYSTEM_GRANT,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false
};

PermissionDef g_locationTestDefUserGrant = {
    .permissionName = "ohos.permission.locationtest2",
    .bundleName = "accesstoken_location_test",
    .grantMode = GrantMode::USER_GRANT,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false
};

PermissionStateFull g_locationTestStateSystemGrant = {
    .permissionName = "ohos.permission.locationtest1",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};

PermissionStateFull g_locationTestStateUserGrant = {
    .permissionName = "ohos.permission.locationtest2",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
};

PermissionStateFull g_locationTestStateVague02 = {
    .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
};

PermissionStateFull g_locationTestStateVague10 = {
    .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
};

PermissionStateFull g_locationTestStateVague12 = {
    .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
};

PermissionStateFull g_locationTestStateAccurate02 = {
    .permissionName = "ohos.permission.LOCATION",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
};

PermissionStateFull g_locationTestStateAccurate10 = {
    .permissionName = "ohos.permission.LOCATION",
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
};

HapInfoParams g_infoManagerTestNormalInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "test2",
    .apiVersion = DEFAULT_API_VERSION,
    .isSystemApp = false
};

HapInfoParams g_infoManagerTestSystemInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "test2",
    .apiVersion = DEFAULT_API_VERSION,
    .isSystemApp = true
};
uint64_t g_selfShellTokenId;
}

void GetNativeToken()
{
    uint64_t tokenId;
    const char **perms = new const char *[4];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
    perms[2] = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS"; // 2 means the second permission
    perms[3] = "ohos.permission.GET_SENSITIVE_PERMISSIONS"; // 3 means the third permission

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 4,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
    };

    infoInstance.processName = "TestCase";
    tokenId = GetAccessTokenId(&infoInstance);
    EXPECT_EQ(0, SetSelfTokenID(tokenId));
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

void AccessTokenKitExtensionTest::SetUpTestCase()
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

    GetNativeToken();
}

void AccessTokenKitExtensionTest::TearDownTestCase()
{
}

void PreparePermStateListExt(HapPolicyParams &policy)
{
    PermissionStateFull permStatAlpha = {
        .permissionName = TEST_PERMISSION_NAME_ALPHA,
        .isGeneral = true,
        .resDeviceID = {"device"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };

    PermissionStateFull permStatBeta = {
        .permissionName = TEST_PERMISSION_NAME_BETA,
        .isGeneral = true,
        .resDeviceID = {"device"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
    };

    PermissionStateFull permTestState5 = {
        .permissionName = "ohos.permission.GET_SENSITIVE_PERMISSIONS",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
    };

    PermissionStateFull permTestState6 = {
        .permissionName = "ohos.permission.DISABLE_PERMISSION_DIALOG",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
    };
    policy.permStateList.emplace_back(permStatAlpha);
    policy.permStateList.emplace_back(permStatBeta);
    policy.permStateList.emplace_back(permTestState5);
    policy.permStateList.emplace_back(permTestState6);
}

void PreparePermStateList(HapPolicyParams &policy)
{
    PermissionStateFull permTestState1 = {
        .permissionName = "ohos.permission.LOCATION",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG},
    };

    PermissionStateFull permTestState2 = {
        .permissionName = "ohos.permission.MICROPHONE",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };

    PermissionStateFull permTestState3 = {
        .permissionName = "ohos.permission.WRITE_CALENDAR",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
    };

    PermissionStateFull permTestState4 = {
        .permissionName = "ohos.permission.READ_IMAGEVIDEO",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };
    policy.permStateList.emplace_back(permTestState1);
    policy.permStateList.emplace_back(permTestState2);
    policy.permStateList.emplace_back(permTestState3);
    policy.permStateList.emplace_back(permTestState4);
    PreparePermStateListExt(policy);
}

void PreparePermDefList(HapPolicyParams &policy)
{
    PermissionDef permissionDefAlpha;
    permissionDefAlpha.permissionName = TEST_PERMISSION_NAME_ALPHA;
    permissionDefAlpha.bundleName = TEST_BUNDLE_NAME;
    permissionDefAlpha.grantMode = GrantMode::USER_GRANT;
    permissionDefAlpha.availableLevel = APL_NORMAL;
    permissionDefAlpha.provisionEnable = false;
    permissionDefAlpha.distributedSceneEnable = false;

    PermissionDef permissionDefBeta;
    permissionDefBeta.permissionName = TEST_PERMISSION_NAME_BETA;
    permissionDefBeta.bundleName = TEST_BUNDLE_NAME;
    permissionDefBeta.grantMode = GrantMode::SYSTEM_GRANT;
    permissionDefBeta.availableLevel = APL_NORMAL;
    permissionDefBeta.provisionEnable = false;
    permissionDefBeta.distributedSceneEnable = false;

    policy.permList.emplace_back(permissionDefAlpha);
    policy.permList.emplace_back(permissionDefBeta);
}

void AccessTokenKitExtensionTest::SetUp()
{
    selfTokenId_ = GetSelfTokenID();
    g_infoManagerTestInfoParms = g_infoManagerTestInfoParmsBak;
    g_infoManagerTestPolicyPrams = g_infoManagerTestPolicyPramsBak;
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "appIDDesc",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = true
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    PreparePermDefList(policy);
    PreparePermStateList(policy);
    policy.permStateList.emplace_back(g_grantPermissionReq);
    policy.permStateList.emplace_back(g_revokePermissionReq);
    AccessTokenKit::AllocHapToken(info, policy);
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
}

void AccessTokenKitExtensionTest::TearDown()
{
    AccessTokenID tokenId = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
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

void AccessTokenKitExtensionTest::AllocHapToken(std::vector<PermissionDef>& permissionDefs,
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

unsigned int AccessTokenKitExtensionTest::GetAccessTokenID(int userID, std::string bundleName, int instIndex)
{
    return AccessTokenKit::GetHapTokenID(userID, bundleName, instIndex);
}

/**
 * @tc.name: GetPermissionFlag006
 * @tc.desc: Get permission flag after grant permission.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitExtensionTest, GetPermissionFlag006, TestSize.Level1)
{
    static PermissionStateFull infoManagerTestStateA = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local2"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
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

    int ret = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.CAMERA", PERMISSION_POLICY_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    uint32_t flag;
    ret = AccessTokenKit::GetPermissionFlag(tokenID, "ohos.permission.CAMERA", flag);
    ASSERT_EQ(PERMISSION_POLICY_FIXED, flag);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: DumpTokenInfo001
 * @tc.desc: Get dump token information with invalid tokenID
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(AccessTokenKitExtensionTest, DumpTokenInfo001, TestSize.Level1)
{
    SetSelfTokenID(g_selfShellTokenId);
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = 123;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    ASSERT_EQ("invalid tokenId", dumpInfo);
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
 * @tc.name: RegisterSelfPermStateChangeCallback001
 * @tc.desc: RegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, RegisterSelfPermStateChangeCallback001, TestSize.Level1)
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
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(selfTokenId_);

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

    SetSelfTokenID(tokenID);
    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(selfTokenId_);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback002
 * @tc.desc: RegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, RegisterSelfPermStateChangeCallback002, TestSize.Level1)
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
        .permList = {},
        .permStateList = {infoManagerTestStateA, infoManagerTestStateB}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr));
    SetSelfTokenID(selfTokenId_);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(tokenID, "ohos.permission.CAMERA", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RevokePermission(tokenID, "ohos.permission.CAMERA", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(tokenID, "ohos.permission.GET_BUNDLE_INFO", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(false, callbackPtr->ready_);

    SetSelfTokenID(tokenID);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr));
    SetSelfTokenID(selfTokenId_);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback003
 * @tc.desc: RegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, RegisterSelfPermStateChangeCallback003, TestSize.Level1)
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
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(selfTokenId_);

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

    SetSelfTokenID(tokenID);
    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(selfTokenId_);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback004
 * @tc.desc: RegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, RegisterSelfPermStateChangeCallback004, TestSize.Level1)
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
        .permList = {},
        .permStateList = {infoManagerTestStateA, infoManagerTestStateB}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA", "ohos.permission.GET_BUNDLE_INFO"};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr));
    SetSelfTokenID(selfTokenId_);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(tokenID, "ohos.permission.CAMERA", 2));
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RevokePermission(tokenID, "ohos.permission.CAMERA", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(tokenID, "ohos.permission.GET_BUNDLE_INFO", 2));
    EXPECT_EQ(true, callbackPtr->ready_);

    callbackPtr->ready_ = false;

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RevokePermission(tokenID, "ohos.permission.GET_BUNDLE_INFO", 2));
    usleep(500000); // 500000us = 0.5s
    EXPECT_EQ(true, callbackPtr->ready_);

    SetSelfTokenID(tokenID);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback005
 * @tc.desc: RegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, RegisterSelfPermStateChangeCallback005, TestSize.Level1)
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
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.INVALID"};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr1 = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr1->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr1);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);

    scopeInfo.permList = {"ohos.permission.INVALID", "ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(selfTokenId_);

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

    SetSelfTokenID(tokenID);
    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback006
 * @tc.desc: RegisterSelfPermStateChangeCallback with permList, whose size is 1024/1025
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, RegisterSelfPermStateChangeCallback006, TestSize.Level1)
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
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    SetSelfTokenID(tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {tokenID};
    for (int32_t i = 1; i <= 1025; i++) { // 1025 is a invalid size
        scopeInfo.permList.emplace_back("ohos.permission.GET_BUNDLE_INFO");
        if (i == 1025) { // 1025 is a invalid size
            auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
            int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
            ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);
            break;
        }
        auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
        int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
        ASSERT_EQ(RET_SUCCESS, res);
        res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
        ASSERT_EQ(RET_SUCCESS, res);
    }
    SetSelfTokenID(selfTokenId_);

    int32_t res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback007
 * @tc.desc: RegisterSelfPermStateChangeCallback without set TokenID.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, RegisterSelfPermStateChangeCallback007, TestSize.Level1)
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
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback008
 * @tc.desc: RegisterSelfPermStateChangeCallback with none or two tokenIDs.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, RegisterSelfPermStateChangeCallback008, TestSize.Level1)
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
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    HapInfoParams g_infoManagerTestInfoParms2 = {
        .userID = 1,
        .bundleName = "accesstoken_test_2",
        .instIndex = 0,
        .appIDDesc = "test2",
        .apiVersion = DEFAULT_API_VERSION
    };

    AccessTokenIDEx tokenIdEx2 = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms2,
        infoManagerTestPolicyPrams1);
    AccessTokenID tokenID2 = tokenIdEx2.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID2);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr1 = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr1->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr1);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);

    scopeInfo.tokenIDs = {tokenID, tokenID2};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);

    SetSelfTokenID(selfTokenId_);
    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
    res = AccessTokenKit::DeleteToken(tokenID2);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback009
 * @tc.desc: RegisterSelfPermStateChangeCallback
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, RegisterSelfPermStateChangeCallback009, TestSize.Level1)
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
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {tokenID};
    std::vector<std::shared_ptr<CbCustomizeTest>> callbackList;
    SetSelfTokenID(tokenID);

    for (int32_t i = 0; i < 200; i++) { // 200 is the max size
        if (i == 200) { // 200 is the max size
            auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
            int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
            ASSERT_EQ(AccessTokenError::ERR_CALLBACKS_EXCEED_LIMITATION, res);
            break;
        }
        auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
        int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
        ASSERT_EQ(RET_SUCCESS, res);
        callbackList.emplace_back(callbackPtr);
    }
    for (int32_t i = 0; i < 200; i++) { // release 200 callback
        auto callbackPtr = callbackList[i];
        int32_t res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
        ASSERT_EQ(RET_SUCCESS, res);
    }
    callbackList.clear();
    SetSelfTokenID(selfTokenId_);
    
    int32_t res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback010
 * @tc.desc: RegisterSelfPermStateChangeCallback with nullptr
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, RegisterSelfPermStateChangeCallback010, TestSize.Level1)
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
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(nullptr);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, res);
    SetSelfTokenID(selfTokenId_);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: UnRegisterSelfPermStateChangeCallback001
 * @tc.desc: UnRegisterSelfPermStateChangeCallback with invalid input.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, UnRegisterSelfPermStateChangeCallback001, TestSize.Level1)
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
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(AccessTokenError::ERR_INTERFACE_NOT_USED_TOGETHER, res);
    SetSelfTokenID(selfTokenId_);
}

/**
 * @tc.name: UnRegisterSelfPermStateChangeCallback002
 * @tc.desc: UnRegisterSelfPermStateChangeCallback repeatedly.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, UnRegisterSelfPermStateChangeCallback002, TestSize.Level1)
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
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(AccessTokenError::ERR_CALLBACK_ALREADY_EXIST, res);
    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(AccessTokenError::ERR_INTERFACE_NOT_USED_TOGETHER, res);
    SetSelfTokenID(selfTokenId_);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: UnRegisterSelfPermStateChangeCallback003
 * @tc.desc: UnRegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, UnRegisterSelfPermStateChangeCallback003, TestSize.Level1)
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
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(selfTokenId_);

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

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: UnRegisterSelfPermStateChangeCallback004
 * @tc.desc: UnRegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, UnRegisterSelfPermStateChangeCallback004, TestSize.Level1)
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
        .permList = {},
        .permStateList = {infoManagerTestStateA, infoManagerTestStateB}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(selfTokenId_);

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

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: UnRegisterSelfPermStateChangeCallback005
 * @tc.desc: UnRegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, UnRegisterSelfPermStateChangeCallback005, TestSize.Level1)
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
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(selfTokenId_);

    SetSelfTokenID(tokenID);
    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(selfTokenId_);

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

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: UnRegisterSelfPermStateChangeCallback006
 * @tc.desc: UnRegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, UnRegisterSelfPermStateChangeCallback006, TestSize.Level1)
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
        .permList = {},
        .permStateList = {infoManagerTestStateA, infoManagerTestStateB}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA", "ohos.permission.GET_BUNDLE_INFO"};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr));
    SetSelfTokenID(selfTokenId_);

    callbackPtr->ready_ = false;

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(tokenID, "ohos.permission.CAMERA", 2));
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(false, callbackPtr->ready_);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RevokePermission(tokenID, "ohos.permission.CAMERA", 2));
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(false, callbackPtr->ready_);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(tokenID, "ohos.permission.GET_BUNDLE_INFO", 2));
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(false, callbackPtr->ready_);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RevokePermission(tokenID, "ohos.permission.GET_BUNDLE_INFO", 2));
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(false, callbackPtr->ready_);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: UnRegisterSelfPermStateChangeCallback007
 * @tc.desc: UnRegisterSelfPermStateChangeCallback permList
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, UnRegisterSelfPermStateChangeCallback007, TestSize.Level1)
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
        .permList = {},
        .permStateList = {infoManagerTestStateA}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams1);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.INVALID", "ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;

    SetSelfTokenID(tokenID);
    int32_t res = AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
    SetSelfTokenID(selfTokenId_);

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

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: GetVersion001
 * @tc.desc: GetVersion caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, GetVersion001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestNormalInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    uint32_t version;
    int32_t res = AccessTokenKit::GetVersion(version);
    ASSERT_EQ(ERR_NOT_SYSTEM_APP, res);
}

/**
 * @tc.name: GetVersion002
 * @tc.desc: GetVersion caller is system app.
 * @tc.type: FUNC
 * @tc.require: issueI5NT1X
 */
HWTEST_F(AccessTokenKitExtensionTest, GetVersion002, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    uint32_t version;
    int32_t res = AccessTokenKit::GetVersion(version);
    ASSERT_EQ(RET_SUCCESS, res);
    ASSERT_EQ(DEFAULT_TOKEN_VERSION, version);
}

/**
 * @tc.name: PermStateChangeCallback001
 * @tc.desc: PermissionStateChangeCallback::PermStateChangeCallback function test.
 * @tc.type: FUNC
 * @tc.require: issueI61NS6
 */
HWTEST_F(AccessTokenKitExtensionTest, PermStateChangeCallback001, TestSize.Level1)
{
    PermStateChangeInfo result = {
        .permStateChangeType = 0,
        .tokenID = 123,
        .permissionName = "ohos.permission.CAMERA"
    };

    std::shared_ptr<CbCustomizeTest> callbackPtr = nullptr;
    std::shared_ptr<PermissionStateChangeCallback> callback = std::make_shared<PermissionStateChangeCallback>(
        callbackPtr);
    ASSERT_NE(callback, nullptr);

    callback->PermStateChangeCallback(result);
    ASSERT_EQ(callback->customizedCallback_, nullptr);
    callback->Stop();
}

class TestCallBack : public PermissionStateChangeCallbackStub {
public:
    TestCallBack() = default;
    virtual ~TestCallBack() = default;

    void PermStateChangeCallback(PermStateChangeInfo& result)
    {
        GTEST_LOG_(INFO) << "PermStateChangeCallback,  tokenID is " << result.tokenID;
    }
};

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: StateChangeCallbackStub::OnRemoteRequest function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenKitExtensionTest, OnRemoteRequest001, TestSize.Level1)
{
    PermStateChangeInfo info = {
        .permStateChangeType = 0,
        .tokenID = 123,
        .permissionName = "ohos.permission.CAMERA"
    };

    TestCallBack callback;
    PermissionStateChangeInfoParcel infoParcel;
    infoParcel.changeInfo = info;

    OHOS::MessageParcel data;
    std::string descriptor = "I don't know";
    data.WriteInterfaceToken(OHOS::Str8ToStr16(descriptor));
    ASSERT_EQ(true, data.WriteParcelable(&infoParcel));

    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);
    ASSERT_NE(0,
        callback.OnRemoteRequest(static_cast<uint32_t>(AccesstokenStateChangeInterfaceCode::PERMISSION_STATE_CHANGE),
        data, reply, option)); // descriptor false

    ASSERT_EQ(true, data.WriteInterfaceToken(IPermissionStateCallback::GetDescriptor()));
    ASSERT_EQ(true, data.WriteParcelable(&infoParcel));
    uint32_t code = 10;
    ASSERT_NE(0, callback.OnRemoteRequest(code, data, reply, option)); // descriptor true + msgCode false
}

/**
 * @tc.name: CreatePermStateChangeCallback001
 * @tc.desc: AccessTokenManagerClient::CreatePermStateChangeCallback function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenKitExtensionTest, CreatePermStateChangeCallback001, TestSize.Level1)
{
    std::vector<std::shared_ptr<CbCustomizeTest>> callbackList;

    uint32_t times = 201;
    for (uint32_t i = 0; i < times; i++) {
        PermStateChangeScope scopeInfo;
        scopeInfo.permList = {};
        scopeInfo.tokenIDs = {};
        auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
        callbackList.emplace_back(callbackPtr);
        int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);

        if (i == 200) {
            EXPECT_EQ(AccessTokenError::ERR_CALLBACKS_EXCEED_LIMITATION, res);
            break;
        }
    }

    for (uint32_t i = 0; i < 200; i++) {
        ASSERT_EQ(0, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackList[i]));
    }

    std::shared_ptr<PermStateChangeCallbackCustomize> customizedCb = nullptr;
    AccessTokenKit::RegisterPermStateChangeCallback(customizedCb); // customizedCb is null
}

/**
 * @tc.name: InitProxy001
 * @tc.desc: AccessTokenManagerClient::InitProxy function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenKitExtensionTest, InitProxy001, TestSize.Level1)
{
    ASSERT_NE(nullptr, AccessTokenManagerClient::GetInstance().proxy_);
    OHOS::sptr<IAccessTokenManager> proxy = AccessTokenManagerClient::GetInstance().proxy_; // backup
    AccessTokenManagerClient::GetInstance().proxy_ = nullptr;
    ASSERT_EQ(nullptr, AccessTokenManagerClient::GetInstance().proxy_);
    AccessTokenManagerClient::GetInstance().InitProxy(); // proxy_ is null
    AccessTokenManagerClient::GetInstance().proxy_ = proxy; // recovery
}

/**
 * @tc.name: AllocHapToken020
 * @tc.desc: AccessTokenKit::AllocHapToken function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenKitExtensionTest, AllocHapToken020, TestSize.Level1)
{
    HapInfoParams info;
    HapPolicyParams policy;
    info.userID = -1;
    AccessTokenKit::AllocHapToken(info, policy);
    ASSERT_EQ(-1, info.userID);
}

/**
 * @tc.name: VerifyAccessToken005
 * @tc.desc: AccessTokenKit::VerifyAccessToken function test
 * @tc.type: FUNC
 * @tc.require: issueI61A6M
 */
HWTEST_F(AccessTokenKitExtensionTest, VerifyAccessToken005, TestSize.Level1)
{
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = "accesstoken_test3",
        .instIndex = 0,
        .appIDDesc = "test3",
        .apiVersion = DEFAULT_API_VERSION
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "test.domain3",
        .permList = {g_infoManagerTestPermDef3},
        .permStateList = {g_infoManagerTestState3}
    };

    AccessTokenKit::AllocHapToken(info, policy);
    AccessTokenID callerTokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, "accesstoken_test3", 0);
    ASSERT_NE(INVALID_TOKENID, callerTokenID);
    AccessTokenID firstTokenID;

    // ret = PERMISSION_GRANTED + firstTokenID = 0
    std::string permissionName = "ohos.permission.GET_BUNDLE_INFO";
    firstTokenID = 0;
    ASSERT_EQ(PermissionState::PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(
        callerTokenID, firstTokenID, permissionName, false));

    firstTokenID = 1;
    // ret = PERMISSION_GRANTED + firstTokenID != 0
    ASSERT_EQ(PermissionState::PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(
        callerTokenID, firstTokenID, permissionName, false));
    AccessTokenKit::DeleteToken(callerTokenID);

    callerTokenID = 0;
    // ret = PERMISSION_DENIED
    ASSERT_EQ(PermissionState::PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(
        callerTokenID, firstTokenID, permissionName, false));
}

/**
 * @tc.name: IsSystemAppByFullTokenIDTest001
 * @tc.desc: check systemapp level by TokenIDEx after AllocHapToken function set isSystemApp true.
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(AccessTokenKitExtensionTest, IsSystemAppByFullTokenIDTest001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms, g_infoManagerTestPolicyPrams);
    AccessTokenIDEx tokenIdEx1 = AccessTokenKit::GetHapTokenIDEx(1, "accesstoken_test", 0);
    ASSERT_EQ(tokenIdEx.tokenIDEx, tokenIdEx1.tokenIDEx);
    bool res = TokenIdKit::IsSystemAppByFullTokenID(tokenIdEx.tokenIDEx);
    ASSERT_EQ(true, res);
    UpdateHapInfoParams info;
    info.appIDDesc = g_infoManagerTestSystemInfoParms.appIDDesc;
    info.apiVersion = g_infoManagerTestSystemInfoParms.apiVersion;
    info.isSystemApp = false;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_infoManagerTestPolicyPrams));
    tokenIdEx1 = AccessTokenKit::GetHapTokenIDEx(1, "accesstoken_test", 0);
    ASSERT_EQ(tokenIdEx.tokenIDEx, tokenIdEx1.tokenIDEx);
    res = TokenIdKit::IsSystemAppByFullTokenID(tokenIdEx.tokenIDEx);
    ASSERT_EQ(false, res);
}

/**
 * @tc.name: IsSystemAppByFullTokenIDTest002
 * @tc.desc: check systemapp level by TokenIDEx after AllocHapToken function set isSystemApp false.
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(AccessTokenKitExtensionTest, IsSystemAppByFullTokenIDTest002, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestNormalInfoParms, g_infoManagerTestPolicyPrams);
    bool res = TokenIdKit::IsSystemAppByFullTokenID(tokenIdEx.tokenIDEx);
    AccessTokenIDEx tokenIdEx1 = AccessTokenKit::GetHapTokenIDEx(1, "accesstoken_test", 0);
    ASSERT_EQ(tokenIdEx.tokenIDEx, tokenIdEx1.tokenIDEx);
    ASSERT_EQ(false, res);
    UpdateHapInfoParams info;
    info.appIDDesc = g_infoManagerTestNormalInfoParms.appIDDesc;
    info.apiVersion = g_infoManagerTestNormalInfoParms.apiVersion;
    info.isSystemApp = true;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_infoManagerTestPolicyPrams));
    tokenIdEx1 = AccessTokenKit::GetHapTokenIDEx(1, "accesstoken_test", 0);
    ASSERT_EQ(tokenIdEx.tokenIDEx, tokenIdEx1.tokenIDEx);
    res = TokenIdKit::IsSystemAppByFullTokenID(tokenIdEx.tokenIDEx);
    ASSERT_EQ(true, res);
}

/**
 * @tc.name: GetRenderTokenIDTest001
 * @tc.desc: TokenIdKit::GetRenderTokenID function test
 * @tc.type: FUNC
 * @tc.require: issueI7MOA1
 */
HWTEST_F(AccessTokenKitExtensionTest, GetRenderTokenIDTest001, TestSize.Level1)
{
    uint64_t validTokenID = GetSelfTokenID();
    uint64_t retTokenId = validTokenID;

    retTokenId = TokenIdKit::GetRenderTokenID(validTokenID);
    ASSERT_NE(retTokenId, validTokenID);
    ASSERT_NE(retTokenId, INVALID_TOKENID);
}

/**
 * @tc.name: GetRenderTokenIDTest002
 * @tc.desc: TokenIdKit::GetRenderTokenID function test
 * @tc.type: FUNC
 * @tc.require: issueI7MOA1
 */
HWTEST_F(AccessTokenKitExtensionTest, GetRenderTokenIDTest002, TestSize.Level1)
{
    uint64_t invalidTokenID = 0;
    uint64_t retTokenId = 1;    /* 1, for testing purposes */

    retTokenId = TokenIdKit::GetRenderTokenID(invalidTokenID);
    ASSERT_EQ(invalidTokenID, retTokenId);
}

/**
 * @tc.name: IsSystemAppByFullTokenIDTest003
 * @tc.desc: check systemapp level by TokenIDEx after AllocHapToken function set isSystemApp false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitExtensionTest, IsSystemAppByFullTokenIDTest003, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms, g_infoManagerTestPolicyPrams);
    AccessTokenIDEx tokenIdEx1 = AccessTokenKit::GetHapTokenIDEx(1, "accesstoken_test", 0);
    ASSERT_EQ(tokenIdEx.tokenIDEx, tokenIdEx1.tokenIDEx);
    bool res = AccessTokenKit::IsSystemAppByFullTokenID(tokenIdEx.tokenIDEx);
    ASSERT_TRUE(res);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: GetRenderTokenIDTest003
 * @tc.desc: AccessTokenKit::GetRenderTokenID function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitExtensionTest, GetRenderTokenIDTest003, TestSize.Level1)
{
    uint64_t invalidTokenID = 0;
    uint64_t retTokenId = 1;    /* 1, for testing purposes */

    retTokenId = AccessTokenKit::GetRenderTokenID(invalidTokenID);
    ASSERT_EQ(invalidTokenID, retTokenId);
}

#ifdef TOKEN_SYNC_ENABLE
namespace {
class TokenSyncCallbackStubTest : public TokenSyncCallbackStub {
public:
    TokenSyncCallbackStubTest() = default;
    virtual ~TokenSyncCallbackStubTest() = default;

    int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) override
    {
        return 0;
    };
    int32_t DeleteRemoteHapTokenInfo(AccessTokenID tokenID) override
    {
        return 0;
    };

    int32_t UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) override
    {
        return 0;
    };
};

static const int32_t FAKE_SYNC_RET = 0xabcdef;
class TokenSyncCallbackImpl : public TokenSyncKitInterface {
public:
    ~TokenSyncCallbackImpl()
    {}

    int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) const override
    {
        LOGI(ATM_DOMAIN, ATM_TAG, "GetRemoteHapTokenInfo called.");
        return FAKE_SYNC_RET;
    };

    int32_t DeleteRemoteHapTokenInfo(AccessTokenID tokenID) const override
    {
        LOGI(ATM_DOMAIN, ATM_TAG, "DeleteRemoteHapTokenInfo called.");
        return FAKE_SYNC_RET;
    };

    int32_t UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) const override
    {
        LOGI(ATM_DOMAIN, ATM_TAG, "UpdateRemoteHapTokenInfo called.");
        return FAKE_SYNC_RET;
    };
};
};

/**
 * @tc.name: TokenSyncCallbackStubTest001
 * @tc.desc: TokenSyncCallbackStub OnRemoteRequest deny test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitExtensionTest, TokenSyncCallbackStubTest001, TestSize.Level1)
{
    TokenSyncCallbackStubTest callback;

    OHOS::MessageParcel data;
    std::string descriptor = "I don't know";
    data.WriteInterfaceToken(OHOS::Str8ToStr16(descriptor));

    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);
    EXPECT_EQ(ERROR_IPC_REQUEST_FAIL,
        callback.OnRemoteRequest(static_cast<uint32_t>(TokenSyncCallbackInterfaceCode::GET_REMOTE_HAP_TOKEN_INFO),
        data, reply, option)); // descriptor false
}

/**
 * @tc.name: TokenSyncCallbackStubTest002
 * @tc.desc: TokenSyncCallbackStub OnRemoteRequest err code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitExtensionTest, TokenSyncCallbackStubTest002, TestSize.Level1)
{
    TokenSyncCallbackStubTest callback;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());

    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);
    EXPECT_NE(0, callback.OnRemoteRequest(static_cast<uint32_t>(0xff), // code false
        data, reply, option));
}

/**
 * @tc.name: TokenSyncCallbackStubTest003
 * @tc.desc: TokenSyncCallbackStub OnRemoteRequest deny call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitExtensionTest, TokenSyncCallbackStubTest003, TestSize.Level1)
{
    TokenSyncCallbackStubTest callback;
    OHOS::MessageParcel data;
    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());

    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);
    EXPECT_EQ(0, callback.OnRemoteRequest(
        static_cast<uint32_t>(TokenSyncCallbackInterfaceCode::GET_REMOTE_HAP_TOKEN_INFO),
        data, reply, option));
    EXPECT_EQ(ERR_IDENTITY_CHECK_FAILED, reply.ReadInt32());

    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());
    EXPECT_EQ(0, callback.OnRemoteRequest(
        static_cast<uint32_t>(TokenSyncCallbackInterfaceCode::DELETE_REMOTE_HAP_TOKEN_INFO),
        data, reply, option));
    EXPECT_EQ(ERR_IDENTITY_CHECK_FAILED, reply.ReadInt32());

    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());
    EXPECT_EQ(0, callback.OnRemoteRequest(
        static_cast<uint32_t>(TokenSyncCallbackInterfaceCode::UPDATE_REMOTE_HAP_TOKEN_INFO),
        data, reply, option));
    EXPECT_EQ(ERR_IDENTITY_CHECK_FAILED, reply.ReadInt32());
}

/**
 * @tc.name: TokenSyncCallbackStubTest004
 * @tc.desc: TokenSyncCallbackStub OnRemoteRequest normal call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitExtensionTest, TokenSyncCallbackStubTest004, TestSize.Level1)
{
    setuid(3020); // ACCESSTOKEN_UID

    TokenSyncCallbackStubTest callback;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());
    data.WriteString("test deviceID"); // test deviceID
    data.WriteUint32(0); // test tokenid
    EXPECT_EQ(0, callback.OnRemoteRequest(
        static_cast<uint32_t>(TokenSyncCallbackInterfaceCode::GET_REMOTE_HAP_TOKEN_INFO),
        data, reply, option));
    EXPECT_EQ(0, reply.ReadInt32());

    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());
    data.WriteUint32(0); // test tokenid
    EXPECT_EQ(0, callback.OnRemoteRequest(
        static_cast<uint32_t>(TokenSyncCallbackInterfaceCode::DELETE_REMOTE_HAP_TOKEN_INFO),
        data, reply, option));
    EXPECT_EQ(0, reply.ReadInt32());

    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());
    HapTokenInfoForSync info;
    HapTokenInfoForSyncParcel tokenInfoParcel;
    tokenInfoParcel.hapTokenInfoForSyncParams = info;
    data.WriteParcelable(&tokenInfoParcel);
    EXPECT_EQ(0, callback.OnRemoteRequest(
        static_cast<uint32_t>(TokenSyncCallbackInterfaceCode::UPDATE_REMOTE_HAP_TOKEN_INFO),
        data, reply, option));
    EXPECT_EQ(0, reply.ReadInt32());
    setuid(0); // root uid
}

/**
 * @tc.name: TokenSyncCallbackTest001
 * @tc.desc: TokenSyncCallback inner call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitExtensionTest, TokenSyncCallbackTest001, TestSize.Level1)
{
    TokenSyncCallback callback(nullptr);
    EXPECT_EQ(nullptr, callback.tokenSyncCallback_); // test input

    std::shared_ptr<TokenSyncKitInterface> ptr = std::make_shared<TokenSyncCallbackImpl>();
    std::shared_ptr<TokenSyncCallback> callbackImpl = std::make_shared<TokenSyncCallback>(ptr);
    EXPECT_NE(nullptr, callbackImpl->tokenSyncCallback_);
    EXPECT_EQ(FAKE_SYNC_RET, callbackImpl->GetRemoteHapTokenInfo("test", 0)); // test input
    EXPECT_EQ(FAKE_SYNC_RET, callbackImpl->DeleteRemoteHapTokenInfo(0)); // test input
    HapTokenInfoForSync info;
    EXPECT_EQ(FAKE_SYNC_RET, callbackImpl->UpdateRemoteHapTokenInfo(info)); // test input
}
#endif // TOKEN_SYNC_ENABLE

/**
 * @tc.name: GetPermissionManagerInfo001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitExtensionTest, GetPermissionManagerInfo001, TestSize.Level1)
{
    PermissionGrantInfo info;
    AccessTokenKit::GetPermissionManagerInfo(info);
    ASSERT_EQ(false, info.grantBundleName.empty());
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

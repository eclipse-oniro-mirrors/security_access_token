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
#include "test_common.h"
#include <thread>
#include "atm_tools_param_info.h"
#include "gtest/gtest.h"
#include "test_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::mutex g_lockSetToken;
uint64_t g_shellTokenId = 0;
HapInfoParams TestCommon::GetInfoManagerTestInfoParms()
{
    HapInfoParams g_infoManagerTestInfoParms = {
        .userID = 1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .appIDDesc = "test3",
        .apiVersion = 8,
        .appDistributionType = "enterprise_mdm"
    };
    return g_infoManagerTestInfoParms;
}

HapInfoParams TestCommon::GetInfoManagerTestNormalInfoParms()
{
    HapInfoParams g_infoManagerTestNormalInfoParms = {
        .userID = 1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .appIDDesc = "test3",
        .apiVersion = 8,
        .isSystemApp = false
    };
    return g_infoManagerTestNormalInfoParms;
}

HapInfoParams TestCommon::GetInfoManagerTestSystemInfoParms()
{
    HapInfoParams g_infoManagerTestSystemInfoParms = {
        .userID = 1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .appIDDesc = "test3",
        .apiVersion = 8,
        .isSystemApp = true
    };
    return g_infoManagerTestSystemInfoParms;
}

HapPolicyParams TestCommon::GetInfoManagerTestPolicyPrams()
{
    PermissionDef g_infoManagerTestPermDef1 = {
        .permissionName = "ohos.permission.test1",
        .bundleName = "accesstoken_test",
        .grantMode = 1,
        .availableLevel = APL_NORMAL,
        .label = "label3",
        .labelId = 1,
        .description = "open the door",
        .descriptionId = 1,
        .availableType = MDM
    };

    PermissionDef g_infoManagerTestPermDef2 = {
        .permissionName = "ohos.permission.test2",
        .bundleName = "accesstoken_test",
        .grantMode = 1,
        .availableLevel = APL_NORMAL,
        .label = "label3",
        .labelId = 1,
        .description = "break the door",
        .descriptionId = 1,
    };

    PermissionStateFull g_infoManagerTestState1 = {
        .permissionName = "ohos.permission.GET_WIFI_INFO",
        .isGeneral = true,
        .resDeviceID = {"local3"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };

    PermissionStateFull g_infoManagerTestState2 = {
        .permissionName = "ohos.permission.SET_WIFI_INFO",
        .isGeneral = false,
        .resDeviceID = {"device 1", "device 2"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED, PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET, PermissionFlag::PERMISSION_USER_FIXED}
    };

    HapPolicyParams g_infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain3",
        .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
        .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
    };
    return g_infoManagerTestPolicyPrams;
}

HapPolicyParams TestCommon::GetTestPolicyParams()
{
    PermissionStateFull g_testPermReq = {
        .permissionName = "ohos.permission.MANAGE_HAP_TOKENID",
        .isGeneral = true,
        .resDeviceID = {"test_device"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
    };
    HapPolicyParams g_testPolicyParams = {
        .apl = APL_SYSTEM_CORE,
        .domain = "test_domain",
        .permStateList = { g_testPermReq },
        .aclRequestedList = {},
        .preAuthorizationInfo = {}
    };
    return g_testPolicyParams;
}

void TestCommon::GetHapParams(HapInfoParams& infoParams, HapPolicyParams& policyParams)
{
    infoParams.userID = 0;
    infoParams.bundleName = "com.ohos.AccessTokenTestBundle";
    infoParams.instIndex = 0;
    infoParams.appIDDesc = "AccessTokenTestAppID";
    infoParams.apiVersion = DEFAULT_API_VERSION;
    infoParams.isSystemApp = true;
    infoParams.appDistributionType = "";

    policyParams.apl = APL_NORMAL;
    policyParams.domain = "accesstoken_test_domain";
    policyParams.permList = {};
    policyParams.permStateList = {};
    policyParams.aclRequestedList = {};
    policyParams.preAuthorizationInfo = {};
}

void TestCommon::TestPreparePermStateList(HapPolicyParams &policy)
{
    PermissionStateFull permStatMicro = {
        .permissionName = "ohos.permission.MICROPHONE",
        .isGeneral = true,
        .resDeviceID = {"device3"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };
    PermissionStateFull permStatCamera = {
        .permissionName = "ohos.permission.SET_WIFI_INFO",
        .isGeneral = true,
        .resDeviceID = {"device3"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
    };
    PermissionStateFull permStatAlpha = {
        .permissionName = "ohos.permission.ALPHA",
        .isGeneral = true,
        .resDeviceID = {"device3"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };
    PermissionStateFull permStatBeta = {
        .permissionName = "ohos.permission.BETA",
        .isGeneral = true,
        .resDeviceID = {"device3"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
    };
    policy.permStateList.emplace_back(permStatMicro);
    policy.permStateList.emplace_back(permStatCamera);
    policy.permStateList.emplace_back(permStatAlpha);
    policy.permStateList.emplace_back(permStatBeta);
}

void TestCommon::TestPreparePermDefList(HapPolicyParams &policy)
{
    PermissionDef permissionDefBeta;
    permissionDefBeta.permissionName = "ohos.permission.BETA";
    permissionDefBeta.bundleName = "ohos";
    permissionDefBeta.grantMode = GrantMode::SYSTEM_GRANT;
    permissionDefBeta.availableLevel = APL_NORMAL;
    permissionDefBeta.provisionEnable = false;
    permissionDefBeta.distributedSceneEnable = false;

    PermissionDef permissionDefAlpha;
    permissionDefAlpha.permissionName = "ohos.permission.ALPHA";
    permissionDefAlpha.bundleName = "ohos";
    permissionDefAlpha.grantMode = GrantMode::USER_GRANT;
    permissionDefAlpha.availableLevel = APL_NORMAL;
    permissionDefAlpha.provisionEnable = false;
    permissionDefAlpha.distributedSceneEnable = false;

    policy.permList.emplace_back(permissionDefBeta);
    policy.permList.emplace_back(permissionDefAlpha);
}


void TestCommon::TestPrepareKernelPermissionStatus(HapPolicyParams& policyParams)
{
    PermissionStateFull permissionStatusBasic = {
        .permissionName = "ohos.permission.test_basic",
        .isGeneral = false,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_GRANTED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED}
    };

    PermissionStateFull permissionStateFull001 = permissionStatusBasic;
    permissionStateFull001.permissionName = "ohos.permission.KERNEL_ATM_SELF_USE";
    PermissionStateFull permissionStateFull002 = permissionStatusBasic;
    permissionStateFull002.permissionName = "ohos.permission.MICROPHONE";
    PermissionStateFull permissionStateFull003 = permissionStatusBasic;
    permissionStateFull003.permissionName = "ohos.permission.CAMERA";
    policyParams.permStateList = {permissionStateFull001, permissionStateFull002, permissionStateFull003};
    policyParams.aclExtendedMap["ohos.permission.KERNEL_ATM_SELF_USE"] = "123";
    policyParams.aclExtendedMap["ohos.permission.MICROPHONE"] = "456"; // filtered
    policyParams.aclExtendedMap["ohos.permission.CAMERA"] = "789"; // filtered
}

void TestCommon::SetTestEvironment(uint64_t shellTokenId)
{
    std::lock_guard<std::mutex> lock(g_lockSetToken);
    g_shellTokenId = shellTokenId;
}

void TestCommon::ResetTestEvironment()
{
    std::lock_guard<std::mutex> lock(g_lockSetToken);
    g_shellTokenId = 0;
}

uint64_t TestCommon::GetShellTokenId()
{
    std::lock_guard<std::mutex> lock(g_lockSetToken);
    return g_shellTokenId;
}

int32_t TestCommon::AllocTestHapToken(
    const HapInfoParams& hapInfo, HapPolicyParams& hapPolicy, AccessTokenIDEx& tokenIdEx)
{
    uint64_t selfTokenId = GetSelfTokenID();
    for (auto& permissionStateFull : hapPolicy.permStateList) {
        PermissionDef permDefResult;
        if (AccessTokenKit::GetDefPermission(permissionStateFull.permissionName, permDefResult) != RET_SUCCESS) {
            continue;
        }
        if (permDefResult.availableLevel > hapPolicy.apl) {
            hapPolicy.aclRequestedList.emplace_back(permissionStateFull.permissionName);
        }
    }
    if (TestCommon::GetNativeTokenIdFromProcess("foundation") == selfTokenId) {
        return AccessTokenKit::InitHapToken(hapInfo, hapPolicy, tokenIdEx);
    }

    // set sh token for self
    MockNativeToken mock("foundation");
    int32_t ret = AccessTokenKit::InitHapToken(hapInfo, hapPolicy, tokenIdEx);

    // restore
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId));

    return ret;
}

AccessTokenIDEx TestCommon::AllocAndGrantHapTokenByTest(const HapInfoParams& info, HapPolicyParams& policy)
{
    for (const auto& permissionStateFull : policy.permStateList) {
        PermissionDef permDefResult;
        if (AccessTokenKit::GetDefPermission(permissionStateFull.permissionName, permDefResult) != RET_SUCCESS) {
            continue;
        }
        if (permDefResult.availableLevel > policy.apl) {
            policy.aclRequestedList.emplace_back(permissionStateFull.permissionName);
        }
    }

    AccessTokenIDEx tokenIdEx = {0};
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(tokenId, INVALID_TOKENID);

    for (const auto& permissionStateFull : policy.permStateList) {
        if (permissionStateFull.grantStatus[0] == PERMISSION_GRANTED) {
            TestCommon::GrantPermissionByTest(
                tokenId, permissionStateFull.permissionName, permissionStateFull.grantFlags[0]);
        } else {
            TestCommon::RevokePermissionByTest(
                tokenId, permissionStateFull.permissionName, permissionStateFull.grantFlags[0]);
        }
    }
    return tokenIdEx;
}

int32_t TestCommon::DeleteTestHapToken(AccessTokenID tokenID)
{
    uint64_t selfTokenId = GetSelfTokenID();
    if (TestCommon::GetNativeTokenIdFromProcess("foundation") == selfTokenId) {
        return AccessTokenKit::DeleteToken(tokenID);
    }

    // set sh token for self
    MockNativeToken mock("foundation");

    int32_t ret = AccessTokenKit::DeleteToken(tokenID);
    // restore
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId));
    return ret;
}

int32_t TestCommon::GrantPermissionByTest(AccessTokenID tokenID, const std::string& permission, uint32_t flag)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
    MockHapToken mock("AccessTokenTestGrant", reqPerm);
    return AccessTokenKit::GrantPermission(tokenID, permission, flag);
}

int32_t TestCommon::RevokePermissionByTest(AccessTokenID tokenID, const std::string& permission, uint32_t flag)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
    MockHapToken mock("AccessTokenTestRevoke", reqPerm);
    return AccessTokenKit::RevokePermission(tokenID, permission, flag);
}

uint64_t TestCommon::GetNativeToken(const char *processName, const char **perms, int32_t permNum)
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permNum,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
        .processName = processName,
    };

    tokenId = GetAccessTokenId(&infoInstance);
    AccessTokenKit::ReloadNativeTokenInfo();
    return tokenId;
}

AccessTokenID TestCommon::GetNativeTokenIdFromProcess(const std::string &process)
{
    uint64_t selfTokenId = GetSelfTokenID();
    EXPECT_EQ(0, SetSelfTokenID(TestCommon::GetShellTokenId())); // set shell token

    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.processName = process;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    size_t pos = dumpInfo.find("\"tokenID\": ");
    if (pos == std::string::npos) {
        return 0;
    }
    pos += std::string("\"tokenID\": ").length();
    std::string numStr;
    while (pos < dumpInfo.length() && std::isdigit(dumpInfo[pos])) {
        numStr += dumpInfo[pos];
        ++pos;
    }
    // restore
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId));

    std::istringstream iss(numStr);
    AccessTokenID tokenID;
    iss >> tokenID;
    return tokenID;
}

// need call by native process
AccessTokenIDEx TestCommon::GetHapTokenIdFromBundle(
    int32_t userID, const std::string& bundleName, int32_t instIndex)
{
    uint64_t selfTokenId = GetSelfTokenID();
    ATokenTypeEnum type = AccessTokenKit::GetTokenTypeFlag(static_cast<AccessTokenID>(selfTokenId));
    if (type != TOKEN_NATIVE) {
        AccessTokenID tokenId1 = GetNativeTokenIdFromProcess("accesstoken_service");
        EXPECT_EQ(0, SetSelfTokenID(tokenId1));
    }
    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(userID, bundleName, instIndex);

    EXPECT_EQ(0, SetSelfTokenID(selfTokenId));
    return tokenIdEx;
}


int32_t TestCommon::GetReqPermissionsByTest(
    AccessTokenID tokenID, std::vector<PermissionStateFull>& permStatList, bool isSystemGrant)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    MockHapToken mock("GetReqPermissionsByTest", reqPerm);
    return AccessTokenKit::GetReqPermissions(tokenID, permStatList, isSystemGrant);
}

int32_t TestCommon::GetPermissionFlagByTest(AccessTokenID tokenID, const std::string& permission, uint32_t& flag)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    MockHapToken mock("GetPermissionFlagByTest", reqPerm, true);
    return AccessTokenKit::GetPermissionFlag(tokenID, permission, flag);
}

MockNativeToken::MockNativeToken(const std::string& process)
{
    selfToken_ = GetSelfTokenID();
    uint32_t tokenId = TestCommon::GetNativeTokenIdFromProcess(process);
    SetSelfTokenID(tokenId);
}

MockNativeToken::~MockNativeToken()
{
    SetSelfTokenID(selfToken_);
}

MockHapToken::MockHapToken(
    const std::string& bundle, const std::vector<std::string>& reqPerm, bool isSystemApp)
{
    selfToken_ = GetSelfTokenID();
    HapInfoParams infoParams = {
        .userID = 0,
        .bundleName = bundle,
        .instIndex = 0,
        .appIDDesc = "AccessTokenTestAppID",
        .apiVersion = TestCommon::DEFAULT_API_VERSION,
        .isSystemApp = isSystemApp,
        .appDistributionType = "",
    };

    HapPolicyParams policyParams = {
        .apl = APL_NORMAL,
        .domain = "accesstoken_test_domain",
    };
    for (size_t i = 0; i < reqPerm.size(); ++i) {
        PermissionDef permDefResult;
        if (AccessTokenKit::GetDefPermission(reqPerm[i], permDefResult) != RET_SUCCESS) {
            continue;
        }
        PermissionStateFull permState = {
            .permissionName = reqPerm[i],
            .isGeneral = true,
            .resDeviceID = {"local3"},
            .grantStatus = {PermissionState::PERMISSION_DENIED},
            .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
        };
        policyParams.permStateList.emplace_back(permState);
        if (permDefResult.availableLevel > policyParams.apl) {
            policyParams.aclRequestedList.emplace_back(reqPerm[i]);
        }
    }

    AccessTokenIDEx tokenIdEx = {0};
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(infoParams, policyParams, tokenIdEx));
    mockToken_= tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(mockToken_, INVALID_TOKENID);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));
}

MockHapToken::~MockHapToken()
{
    if (mockToken_ != INVALID_TOKENID) {
        EXPECT_EQ(0, TestCommon::DeleteTestHapToken(mockToken_));
    }
    EXPECT_EQ(0, SetSelfTokenID(selfToken_));
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
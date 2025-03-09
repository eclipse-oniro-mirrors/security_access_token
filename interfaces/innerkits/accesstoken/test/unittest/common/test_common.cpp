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
#include "gtest/gtest.h"
#include <thread>

namespace OHOS {
namespace Security {
namespace AccessToken {
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
        .permList = {},
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

void TestCommon::TestPrepareKernelPermissionDefinition(
    HapInfoParams& infoParams, HapPolicyParams& policyParams)
{
    PermissionDef permDefBasic = {
        .permissionName = "ohos.permission.test_basic",
        .bundleName = "accesstoken_test",
        .grantMode = 1,
        .availableLevel = APL_SYSTEM_CORE,
        .label = "label",
        .labelId = 1,
        .description = "test",
        .descriptionId = 1,
        .provisionEnable = true,
        .isKernelEffect = true,
        .hasValue = true,
    };

    PermissionDef permDef1 = permDefBasic;
    permDef1.permissionName = "ohos.permission.kernel.ALLOW_WRITABLE_CODE_MEMORY";
    PermissionDef permDef2 = permDefBasic;
    permDef2.permissionName = "ohos.permission.kernel.DISABLE_CODE_MEMORY_PROTECTION";
    permDef2.hasValue = false;
    PermissionDef permDef3 = permDefBasic;
    permDef3.permissionName = "ohos.permission.kernel.ALLOW_EXECUTABLE_FORT_MEMORY";
    permDef3.isKernelEffect = false;

    policyParams.permList = {permDef1, permDef2, permDef3};

    AccessTokenIDEx fullTokenId;

    // update permission definition
    int32_t ret = AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId);
    ASSERT_EQ(RET_SUCCESS, ret);
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
    permissionStateFull001.permissionName = "ohos.permission.kernel.ALLOW_WRITABLE_CODE_MEMORY";
    PermissionStateFull permissionStateFull002 = permissionStatusBasic;
    permissionStateFull002.permissionName = "ohos.permission.kernel.DISABLE_CODE_MEMORY_PROTECTION";
    PermissionStateFull permissionStateFull003 = permissionStatusBasic;
    permissionStateFull003.permissionName = "ohos.permission.kernel.ALLOW_EXECUTABLE_FORT_MEMORY";
    PermissionStateFull permissionStateFull004 = permissionStatusBasic;
    permissionStateFull004.permissionName = "ohos.permission.CAMERA";
    policyParams.permStateList = {permissionStateFull001, permissionStateFull002,
                                  permissionStateFull003, permissionStateFull004};
    policyParams.aclExtendedMap["ohos.permission.kernel.ALLOW_WRITABLE_CODE_MEMORY"] = "123";
    policyParams.aclExtendedMap["ohos.permission.kernel.ALLOW_EXECUTABLE_FORT_MEMORY"] = "456";
    policyParams.aclExtendedMap["ohos.permission.test1"] = "test"; // filtered
    policyParams.aclExtendedMap["ohos.permission.CAMERA"] = "789"; // filtered
}

AccessTokenID TestCommon::AllocTestToken(
    const HapInfoParams& hapInfo, const HapPolicyParams& hapPolicy)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(hapInfo, hapPolicy);
    return tokenIdEx.tokenIdExStruct.tokenID;
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

void TestCommon::GetNativeTokenTest()
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
}  // namespace SecurityComponent
}  // namespace Security
}  // namespace OHOS
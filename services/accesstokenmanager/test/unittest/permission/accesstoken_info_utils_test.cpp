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

#include <gtest/gtest.h>
#include <algorithm>

#include "access_token.h"
#include "accesstoken_info_utils.h"
#include "parameter.h"
#include "permission_data_brief.h"
#include "permission_feature_manager.h"
#include "permission_map.h"
#include "provision/provision_info.h"
#include "token_field_const.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr uint32_t SYSTEM_APP_FLAG = 0x0001;
constexpr uint32_t ATOMIC_SERVICE_FLAG = 0x0002;
constexpr uint32_t DEBUG_APP_FLAG = 0x0008;
constexpr int32_t BASE_USER_RANGE = 200000;
PermissionStatus BuildStatus(const std::string& permissionName, const std::string& feature = "")
{
    PermissionStatus status;
    status.permissionName = permissionName;
    status.feature = feature;
    status.grantStatus = PERMISSION_DENIED;
    status.grantFlag = PERMISSION_DEFAULT_FLAG;
    return status;
}
}

class AccessTokenInfoUtilsTest : public testing::Test {
public:
    void TearDown() override
    {
        PermissionFeatureManager::GetInstance().SetFeatures({});
    }
};

/**
 * @tc.name: BuildBundleFullInfo001
 * @tc.desc: Verify BuildBundleFullInfo fills nocached info and unique permission codes.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, BuildBundleFullInfo001, TestSize.Level0)
{
    BundleParam param;
    param.bundleName = "com.ohos.helper.test";
    param.appIdentifier = 123456;
    param.distributionType = static_cast<int32_t>(Verify::AppDistType::NONE_TYPE);
    param.isDebug = true;
    param.idType = 3;

    HapPolicy policy;
    policy.apl = APL_NORMAL;
    policy.permStateList = {
        BuildStatus("ohos.permission.CAMERA"),
        BuildStatus("ohos.permission.CAMERA"),
        BuildStatus("ohos.permission.MICROPHONE"),
    };

    std::shared_ptr<BundleInfoInner> innerInfo;
    BundleNoCachedInfo noCached;
    AccessTokenInfoUtils::BuildBundleFullInfo(param, policy, innerInfo, noCached);

    ASSERT_NE(nullptr, innerInfo);
    ASSERT_EQ(2u, innerInfo->permCodeList.size());

    uint32_t cameraCode = 0;
    uint32_t microphoneCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", cameraCode));
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.MICROPHONE", microphoneCode));
    EXPECT_NE(innerInfo->permCodeList.end(),
        std::find(innerInfo->permCodeList.begin(), innerInfo->permCodeList.end(), static_cast<uint16_t>(cameraCode)));
    EXPECT_NE(innerInfo->permCodeList.end(), std::find(innerInfo->permCodeList.begin(), innerInfo->permCodeList.end(),
        static_cast<uint16_t>(microphoneCode)));

    EXPECT_EQ(policy.apl, noCached.apl);
    EXPECT_EQ(param.distributionType, noCached.distributionType);
    EXPECT_EQ(param.appIdentifier, noCached.ownerid);
    EXPECT_EQ(3u, noCached.idType);
}

/**
 * @tc.name: BuildBundleFullInfo002
 * @tc.desc: Verify system app permissions are filtered by feature support.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, BuildBundleFullInfo002, TestSize.Level0)
{
    BundleParam param;
    param.bundleName = "com.ohos.helper.system";
    param.isSystem = true;

    HapPolicy policy;
    policy.apl = APL_NORMAL;
    policy.permStateList = {
        BuildStatus("ohos.permission.CAMERA", "unsupported.feature"),
        BuildStatus("ohos.permission.USE_BLUETOOTH"),
    };
    PermissionFeatureManager::GetInstance().SetFeatures({});

    std::shared_ptr<BundleInfoInner> innerInfo;
    BundleNoCachedInfo noCached;
    AccessTokenInfoUtils::BuildBundleFullInfo(param, policy, innerInfo, noCached);

    ASSERT_NE(nullptr, innerInfo);
    ASSERT_EQ(1u, innerInfo->permCodeList.size());

    uint32_t bluetoothCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.USE_BLUETOOTH", bluetoothCode));
    EXPECT_EQ(static_cast<uint16_t>(bluetoothCode), innerInfo->permCodeList[0]);
}

/**
 * @tc.name: BuildHapTokenInfo001
 * @tc.desc: Verify BuildHapTokenInfo fills token base fields and token attributes.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, BuildHapTokenInfo001, TestSize.Level0)
{
    Identity id = {};
    id.uid = 20100042;
    id.appUid = 20100042;
    id.tokenId = 0x12345678;

    BundleParam param;
    param.bundleName = "com.ohos.helper.build";
    param.apiVersion = 1205;
    param.isSystem = true;
    param.isAtomicService = true;
    param.isDebug = true;

    HapTokenInfo info;
    AccessTokenInfoUtils::BuildHapTokenInfo(id, param, info);

    EXPECT_EQ(static_cast<AccessTokenID>(id.tokenId & 0xffffffff), info.tokenID);
    EXPECT_EQ(id.uid / BASE_USER_RANGE, info.userID);
    EXPECT_EQ(param.bundleName, info.bundleName);
    EXPECT_EQ(205, info.apiVersion);
    EXPECT_EQ(DEFAULT_TOKEN_VERSION, info.ver);
    EXPECT_EQ(DLP_COMMON, info.dlpType);
    EXPECT_NE(0u, info.tokenAttr & SYSTEM_APP_FLAG);
    EXPECT_NE(0u, info.tokenAttr & ATOMIC_SERVICE_FLAG);
    EXPECT_NE(0u, info.tokenAttr & DEBUG_APP_FLAG);
}

/**
 * @tc.name: BuildHapTokenInfo002
 * @tc.desc: Verify BuildHapTokenInfo leaves optional attribute bits cleared when flags are false.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, BuildHapTokenInfo002, TestSize.Level0)
{
    Identity id = {};
    id.uid = 400000;
    id.appUid = 400000;
    id.tokenId = 0x87654321;

    BundleParam param;
    param.bundleName = "com.ohos.helper.plain";
    param.apiVersion = 12;

    HapTokenInfo info;
    AccessTokenInfoUtils::BuildHapTokenInfo(id, param, info);

    EXPECT_EQ(12, info.apiVersion);
    EXPECT_EQ(0u, info.tokenAttr & SYSTEM_APP_FLAG);
    EXPECT_EQ(0u, info.tokenAttr & ATOMIC_SERVICE_FLAG);
    EXPECT_EQ(0u, info.tokenAttr & DEBUG_APP_FLAG);
}

/**
 * @tc.name: BuildHapTokenInfo003
 * @tc.desc: Verify userID is derived from appUid (not uid) when uid differs from appUid after uid switch.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, BuildHapTokenInfo003, TestSize.Level0)
{
    Identity id = {};
    id.uid = 100; // 100: switched uid (user id), differs from appUid
    id.appUid = 20010001;
    id.tokenId = 0x12345678;

    BundleParam param;
    param.bundleName = "com.ohos.helper.splituid";
    param.apiVersion = 12;

    HapTokenInfo info;
    AccessTokenInfoUtils::BuildHapTokenInfo(id, param, info);

    EXPECT_EQ(id.appUid / BASE_USER_RANGE, info.userID);
    EXPECT_EQ(100, info.userID);
    EXPECT_EQ(id.appUid, info.uid);
    EXPECT_EQ(20010001, info.uid);
}

/**
 * @tc.name: IsSystemResource001
 * @tc.desc: Verify system resource bundle is identified correctly.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, IsSystemResource001, TestSize.Level0)
{
    EXPECT_TRUE(AccessTokenInfoUtils::IsSystemResource("ohos.global.systemres"));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSystemResource("com.ohos.helper.test"));
}

/**
 * @tc.name: CheckSpecifiedFlag001
 * @tc.desc: Verify token attribute flag helper detects enabled bits.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, CheckSpecifiedFlag001, TestSize.Level0)
{
    uint32_t tokenAttr = SYSTEM_APP_FLAG | DEBUG_APP_FLAG;
    EXPECT_TRUE(AccessTokenInfoUtils::CheckSpecifiedFlag(tokenAttr, SYSTEM_APP_FLAG));
    EXPECT_TRUE(AccessTokenInfoUtils::CheckSpecifiedFlag(tokenAttr, DEBUG_APP_FLAG));
    EXPECT_FALSE(AccessTokenInfoUtils::CheckSpecifiedFlag(tokenAttr, ATOMIC_SERVICE_FLAG));
}

/**
 * @tc.name: BuildBundleFullInfo003
 * @tc.desc: Verify unknown permissions are skipped when building bundle info.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, BuildBundleFullInfo003, TestSize.Level0)
{
    BundleParam param;
    param.bundleName = "com.ohos.helper.unknown";

    HapPolicy policy;
    policy.apl = APL_NORMAL;
    policy.permStateList = {BuildStatus("ohos.permission.unknown")};

    std::shared_ptr<BundleInfoInner> innerInfo;
    BundleNoCachedInfo noCached;
    AccessTokenInfoUtils::BuildBundleFullInfo(param, policy, innerInfo, noCached);

    ASSERT_NE(nullptr, innerInfo);
    EXPECT_TRUE(innerInfo->permCodeList.empty());
}

/**
 * @tc.name: BuildBundleFullInfo004
 * @tc.desc: Verify permissions failing acl check are skipped when building bundle info.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, BuildBundleFullInfo004, TestSize.Level0)
{
    BundleParam param;
    param.bundleName = "com.ohos.helper.acl";

    HapPolicy policy;
    policy.apl = APL_NORMAL;
    policy.permStateList = {BuildStatus("ohos.permission.GET_ALL_APP_ACCOUNTS")};

    std::shared_ptr<BundleInfoInner> innerInfo;
    BundleNoCachedInfo noCached;
    AccessTokenInfoUtils::BuildBundleFullInfo(param, policy, innerInfo, noCached);

    ASSERT_NE(nullptr, innerInfo);
    EXPECT_TRUE(innerInfo->permCodeList.empty());
}

/**
 * @tc.name: BuildBundleFullInfo005
 * @tc.desc: Verify permissions failing range check are skipped when building bundle info.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, BuildBundleFullInfo005, TestSize.Level0)
{
    BundleParam param;
    param.bundleName = "com.ohos.helper.range";
    param.distributionType = static_cast<int32_t>(Verify::AppDistType::APP_GALLERY);

    HapPolicy policy;
    policy.apl = APL_NORMAL;
    policy.aclRequestedList = {"ohos.permission.ENTERPRISE_MANAGE_SETTINGS"};
    policy.permStateList = {BuildStatus("ohos.permission.ENTERPRISE_MANAGE_SETTINGS")};

    std::shared_ptr<BundleInfoInner> innerInfo;
    BundleNoCachedInfo noCached;
    AccessTokenInfoUtils::BuildBundleFullInfo(param, policy, innerInfo, noCached);

    ASSERT_NE(nullptr, innerInfo);
    EXPECT_TRUE(innerInfo->permCodeList.empty());
}

/**
 * @tc.name: GetReservedTokenTypeDBValue001
 * @tc.desc: Verify GetReservedTokenTypeDBValue returns the persisted reserved type value.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, GetReservedTokenTypeDBValue001, TestSize.Level0)
{
    GenericValues values;
#ifdef SPM_DATA_ENABLE
    values.Put(TokenFiledConst::FIELD_RESERVED, static_cast<int32_t>(ReservedType::RESERVED_DATA));
    EXPECT_EQ(ReservedType::RESERVED_DATA, AccessTokenInfoUtils::GetReservedTokenTypeDBValue(values));
#else
    values.Put(TokenFiledConst::FIELD_TOKEN_ATTR, 0x0004); // 0x0004: reserved
    EXPECT_EQ(ReservedType::RESERVED_IDENTITY, AccessTokenInfoUtils::GetReservedTokenTypeDBValue(values));
#endif
}

/**
 * @tc.name: GetReservedTokenTypeDBValue002
 * @tc.desc: Verify GetReservedTokenTypeDBValue returns none when no reserved mark is stored.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, GetReservedTokenTypeDBValue002, TestSize.Level0)
{
    GenericValues values;
#ifdef SPM_DATA_ENABLE
    values.Put(TokenFiledConst::FIELD_RESERVED, static_cast<int32_t>(ReservedType::NONE));
#else
    values.Put(TokenFiledConst::FIELD_TOKEN_ATTR, 0);
#endif
    EXPECT_EQ(ReservedType::NONE, AccessTokenInfoUtils::GetReservedTokenTypeDBValue(values));
}

/**
 * @tc.name: BuildBundleFullInfoDisabledPerm001
 * @tc.desc: Verify BuildBundleFullInfo skips permissions whose briefDef.isEnable is false.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, BuildBundleFullInfoDisabledPerm001, TestSize.Level0)
{
    ASSERT_TRUE(SetPermissionBriefEnabled("ohos.permission.CAMERA", false));

    BundleParam param;
    param.bundleName = "com.ohos.helper.disabled";

    HapPolicy policy;
    policy.apl = APL_NORMAL;
    policy.permStateList = {BuildStatus("ohos.permission.CAMERA")};

    std::shared_ptr<BundleInfoInner> innerInfo;
    BundleNoCachedInfo noCached;
    AccessTokenInfoUtils::BuildBundleFullInfo(param, policy, innerInfo, noCached);

    ASSERT_NE(nullptr, innerInfo);
    EXPECT_TRUE(innerInfo->permCodeList.empty());

    SetPermissionBriefEnabled("ohos.permission.CAMERA", true);
}

/**
 * @tc.name: AccessTokenServiceAppVerifyParamSet001
 * @tc.desc: Verify AccessTokenServiceAppVerifyParamSet stores the app verify parameter.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, AccessTokenServiceAppVerifyParamSet001, TestSize.Level0)
{
    AccessTokenInfoUtils::AccessTokenServiceAppVerifyParamSet();

    char value[32] = {0};
    EXPECT_GE(GetParameter(ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY, "", value, sizeof(value) - 1), 0);
    EXPECT_EQ(std::string("1"), std::string(value));

    SetParameter(ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY, "0");
}

/**
 * @tc.name: IsSystemAppVerified001
 * @tc.desc: Verify IsSystemAppVerified reflects the app verify parameter value.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, IsSystemAppVerified001, TestSize.Level0)
{
    SetParameter(ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY, "0");
    EXPECT_FALSE(AccessTokenInfoUtils::IsSystemAppVerified());

    SetParameter(ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY, "1");
    EXPECT_TRUE(AccessTokenInfoUtils::IsSystemAppVerified());

    SetParameter(ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY, "0");
    EXPECT_FALSE(AccessTokenInfoUtils::IsSystemAppVerified());
}

/**
 * @tc.name: IsSystemSpmEnforcing001
 * @tc.desc: Verify IsSystemSpmEnforcing reflects the spm enforcing parameter value.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, IsSystemSpmEnforcing001, TestSize.Level0)
{
    SetParameter(ACCESS_TOKEN_SERVICE_SPM_ENFORCING_KEY, "0");
    EXPECT_FALSE(AccessTokenInfoUtils::IsSystemSpmEnforcing());

    SetParameter(ACCESS_TOKEN_SERVICE_SPM_ENFORCING_KEY, "1");
    EXPECT_TRUE(AccessTokenInfoUtils::IsSystemSpmEnforcing());

    SetParameter(ACCESS_TOKEN_SERVICE_SPM_ENFORCING_KEY, "0");
    EXPECT_FALSE(AccessTokenInfoUtils::IsSystemSpmEnforcing());
}

/**
 * @tc.name: IsSharedUid_001
 * @tc.desc: Verify the sharedUID dimension: with ACCESS_TOKEN_SUPPORT_SHAREDUID enabled sharedUID
 *           switches only when deviceTypes is exactly ["2in1"]; with the feature disabled it
 *           never switches.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, IsSharedUid_001, TestSize.Level0)
{
#ifdef ACCESS_TOKEN_SUPPORT_SHAREDUID
    EXPECT_TRUE(AccessTokenInfoUtils::IsSharedUid(true, {"2in1"}, false));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(true, {"phone"}, false));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(true, {}, false));
#else
    // Feature off: the sharedUID dimension never switches, whatever deviceTypes is.
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(true, {"2in1"}, false));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(true, {"phone"}, false));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(true, {}, false));
#endif
}

/**
 * @tc.name: IsSharedUidDeviceTypesArray001
 * @tc.desc: Full deviceTypes-dimension truth table: with ACCESS_TOKEN_SUPPORT_SHAREDUID enabled
 *           the criterion is hasCustomSandboxPerm || (sharedUID && deviceTypes.size() == 1 &&
 *           deviceTypes[0] == "2in1"); with the feature disabled every combination returns false.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, IsSharedUidDeviceTypesArray001, TestSize.Level0)
{
#ifdef ACCESS_TOKEN_SUPPORT_SHAREDUID
    // sharedUID dimension: only deviceTypes exactly ["2in1"] switches.
    EXPECT_TRUE(AccessTokenInfoUtils::IsSharedUid(true, {"2in1"}, false));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(true, {"phone"}, false));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(true, {"default"}, false));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(true, {}, false));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(true, {"2IN1"}, false));
    // Array-length semantics: any size other than 1 never switches, even when "2in1" is present.
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(true, {"2in1", "phone"}, false));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(true, {"phone", "2in1"}, false));
    // CUSTOM_SANDBOX dimension: switches independently of sharedUID and deviceTypes.
    EXPECT_TRUE(AccessTokenInfoUtils::IsSharedUid(false, {}, true));
    EXPECT_TRUE(AccessTokenInfoUtils::IsSharedUid(false, {"2in1"}, true));
    EXPECT_TRUE(AccessTokenInfoUtils::IsSharedUid(false, {"phone"}, true));
    EXPECT_TRUE(AccessTokenInfoUtils::IsSharedUid(true, {"phone"}, true));
    EXPECT_TRUE(AccessTokenInfoUtils::IsSharedUid(true, {"2in1"}, true));
    EXPECT_TRUE(AccessTokenInfoUtils::IsSharedUid(false, {"2in1", "phone"}, true));
    // Neither dimension: never switches.
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(false, {"2in1"}, false));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(false, {"phone"}, false));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(false, {}, false));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(false, {"2in1", "phone"}, false));
#else
    // Feature off: the criterion is compiled out, every combination returns false.
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(true, {"2in1"}, false));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(true, {"2in1", "phone"}, false));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(true, {"2in1"}, true));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(true, {"phone"}, true));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(false, {"2in1"}, true));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(false, {}, true));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(true, {}, false));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(false, {"2in1"}, false));
    EXPECT_FALSE(AccessTokenInfoUtils::IsSharedUid(false, {}, false));
#endif
}

/**
 * @tc.name: HasCustomSandboxPermission001
 * @tc.desc: Verify HasCustomSandboxPermission reports true when CUSTOM_SANDBOX appears in the
 *           permission state list, alone or among other permissions.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, HasCustomSandboxPermission001, TestSize.Level0)
{
    // Precondition: CUSTOM_SANDBOX is defined and enabled in the device permission table.
    ASSERT_TRUE(IsDefinedPermissionInner("ohos.permission.CUSTOM_SANDBOX"));

    std::vector<PermissionStatus> onlySandbox = {BuildStatus("ohos.permission.CUSTOM_SANDBOX")};
    EXPECT_TRUE(AccessTokenInfoUtils::HasCustomSandboxPermission(onlySandbox));

    std::vector<PermissionStatus> withOthers = {
        BuildStatus("ohos.permission.CAMERA"),
        BuildStatus("ohos.permission.CUSTOM_SANDBOX"),
        BuildStatus("ohos.permission.MICROPHONE"),
    };
    EXPECT_TRUE(AccessTokenInfoUtils::HasCustomSandboxPermission(withOthers));
}

/**
 * @tc.name: HasCustomSandboxPermission002
 * @tc.desc: Verify HasCustomSandboxPermission reports false for an empty list and for lists
 *           holding only other permissions.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, HasCustomSandboxPermission002, TestSize.Level0)
{
    std::vector<PermissionStatus> emptyList;
    EXPECT_FALSE(AccessTokenInfoUtils::HasCustomSandboxPermission(emptyList));

    std::vector<PermissionStatus> otherPerms = {
        BuildStatus("ohos.permission.CAMERA"),
        BuildStatus("ohos.permission.MICROPHONE"),
    };
    EXPECT_FALSE(AccessTokenInfoUtils::HasCustomSandboxPermission(otherPerms));
}

/**
 * @tc.name: HasCustomSandboxPermission003
 * @tc.desc: Verify HasCustomSandboxPermission consults the device definition table: with the
 *           CUSTOM_SANDBOX definition disabled it reports false even when the permission is in
 *           the list, and restoring the definition brings the true result back.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, HasCustomSandboxPermission003, TestSize.Level0)
{
    const std::string customSandbox = "ohos.permission.CUSTOM_SANDBOX";
    std::vector<PermissionStatus> permStateList = {BuildStatus(customSandbox)};
    ASSERT_TRUE(AccessTokenInfoUtils::HasCustomSandboxPermission(permStateList));

    // Between the disable and the restore only EXPECTs run, so no early return can leak the
    // disabled definition into the rest of the single-process suite.
    ASSERT_TRUE(SetPermissionBriefEnabled(customSandbox, false));
    EXPECT_FALSE(IsDefinedPermissionInner(customSandbox));
    EXPECT_FALSE(AccessTokenInfoUtils::HasCustomSandboxPermission(permStateList));
    EXPECT_TRUE(SetPermissionBriefEnabled(customSandbox, true));
    EXPECT_TRUE(IsDefinedPermissionInner(customSandbox));
    EXPECT_TRUE(AccessTokenInfoUtils::HasCustomSandboxPermission(permStateList));
}

/**
 * @tc.name: ResolveHapUidInvalidUid001
 * @tc.desc: ResolveHapUid returns INVALID_UID for an invalid appUid without querying the kernel,
 *           whatever isSharedUid is.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, ResolveHapUidInvalidUid001, TestSize.Level0)
{
    // The isSharedUid flag is irrelevant here: INVALID_UID short-circuits before the kernel
    // version query, so the expectation holds in every build config and on every kernel version.
    EXPECT_EQ(-1, AccessTokenInfoUtils::ResolveHapUid(-1, true));
    EXPECT_EQ(-1, AccessTokenInfoUtils::ResolveHapUid(-1, false));
}

/**
 * @tc.name: ResolveHapUidNoSwitchCondition001
 * @tc.desc: ResolveHapUid keeps appUid when isSharedUid is false, on any kernel version and
 *           in every build config.
 * @tc.type: FUNC
 */
HWTEST_F(AccessTokenInfoUtilsTest, ResolveHapUidNoSwitchCondition001, TestSize.Level0)
{
    constexpr int32_t testAppUid = 20010001;
    // Version-agnostic by design: this target links the real libtokensetproc_shared, so on a
    // non-SPM kernel the version query fails and ResolveHapUid falls back to appUid, while on
    // an SPM kernel the false flag still keeps appUid. Switch-path ON coverage lives in the
    // boot and spm suites, which link the fake setproc instead.
    EXPECT_EQ(testAppUid, AccessTokenInfoUtils::ResolveHapUid(testAppUid, false));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

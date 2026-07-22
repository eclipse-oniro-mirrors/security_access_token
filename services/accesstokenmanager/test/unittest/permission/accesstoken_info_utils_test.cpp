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
    EXPECT_EQ(id.uid, info.uid);
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
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

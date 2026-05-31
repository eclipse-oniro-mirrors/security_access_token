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

#include "access_token.h"
#define private public
#include "dlp_permission_set_manager.h"
#undef private
#include "permission_constraint_check.h"
#include "permission_map.h"
#include "provision/provision_info.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {

constexpr uint32_t SYSTEM_APP_FLAG = 0x0001;
constexpr uint32_t ATOMIC_SERVICE_FLAG = 0x0002;
constexpr uint32_t DEBUG_APP_FLAG = 0x0008;
constexpr int32_t TEST_API_VERSION = 12;
constexpr int32_t OLD_API_VERSION = 9;
constexpr int32_t DEBUG_ID_TYPE = 3;
constexpr int32_t APP_IDENTIFIER_ZERO = 0;
constexpr int32_t APP_IDENTIFIER_ONE = 1;
constexpr int32_t BASE_APP_ID_TYPE = 5;
constexpr int32_t JIT_GRANTED_ID_TYPE = 10;
constexpr int32_t DEFAULT_ID_TYPE = 2;

class PermissionConstraintCheckTest : public testing::Test {};

/**
 * @tc.name: IsAclSatisfied001
 * @tc.desc: Verify permission acl check fails when required acl is absent.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, IsAclSatisfied001, TestSize.Level0)
{
    PermissionBriefDef briefDef = {};
    briefDef.permissionName = const_cast<char *>("ohos.permission.TEST_ACL");
    briefDef.availableLevel = APL_SYSTEM_BASIC;
    briefDef.provisionEnable = true;

    HapPolicy policy = {};
    policy.apl = APL_NORMAL;

    EXPECT_FALSE(PermissionConstraintCheck::IsAclSatisfied(briefDef, policy));
}

/**
 * @tc.name: IsAclSatisfied002
 * @tc.desc: Verify permission acl check passes when extended acl exists.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, IsAclSatisfied002, TestSize.Level0)
{
    PermissionBriefDef briefDef = {};
    briefDef.permissionName = const_cast<char *>("ohos.permission.TEST_EXT");
    briefDef.availableLevel = APL_SYSTEM_BASIC;
    briefDef.provisionEnable = true;
    briefDef.hasValue = true;

    HapPolicy policy = {};
    policy.apl = APL_NORMAL;
    policy.aclExtendedMap[briefDef.permissionName] = "true";

    EXPECT_TRUE(PermissionConstraintCheck::IsAclSatisfied(briefDef, policy));
}

/**
 * @tc.name: IsAclSatisfied003
 * @tc.desc: Verify permission acl check passes when requested acl exists.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, IsAclSatisfied003, TestSize.Level0)
{
    PermissionBriefDef briefDef = {};
    briefDef.permissionName = const_cast<char *>("ohos.permission.TEST_REQUESTED");
    briefDef.availableLevel = APL_SYSTEM_BASIC;
    briefDef.provisionEnable = true;

    HapPolicy policy = {};
    policy.apl = APL_NORMAL;
    policy.aclRequestedList = {briefDef.permissionName};

    EXPECT_TRUE(PermissionConstraintCheck::IsAclSatisfied(briefDef, policy));
}

/**
 * @tc.name: IsPermAvailableRangeSatisfied001
 * @tc.desc: Verify MDM permission is rejected for non-MDM app.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, IsPermAvailableRangeSatisfied001, TestSize.Level0)
{
    BundleParam param = {};
    param.bundleName = "com.example.test";
    param.apiVersion = TEST_API_VERSION;
    param.distributionType = static_cast<int32_t>(Verify::AppDistType::ENTERPRISE_NORMAL);

    PermissionBriefDef briefDef = {};
    briefDef.permissionName = const_cast<char *>("ohos.permission.MDM_TEST");
    briefDef.availableType = ATokenAvailableTypeEnum::MDM;

    PermissionRulesEnum rule = PERMISSION_ACL_RULE;
    EXPECT_FALSE(PermissionConstraintCheck::IsPermAvailableRangeSatisfied(param, briefDef, rule));
    EXPECT_EQ(PERMISSION_EDM_RULE, rule);
}

/**
 * @tc.name: IsPermAvailableRangeSatisfied002
 * @tc.desc: Verify MDM permission passes for debug app.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, IsPermAvailableRangeSatisfied002, TestSize.Level0)
{
    BundleParam param = {};
    param.bundleName = "com.example.test";
    param.apiVersion = TEST_API_VERSION;
    param.isDebug = true;

    PermissionBriefDef briefDef = {};
    briefDef.permissionName = const_cast<char *>("ohos.permission.MDM_TEST");
    briefDef.availableType = ATokenAvailableTypeEnum::MDM;

    PermissionRulesEnum rule = PERMISSION_ACL_RULE;
    EXPECT_TRUE(PermissionConstraintCheck::IsPermAvailableRangeSatisfied(param, briefDef, rule));
    EXPECT_EQ(PERMISSION_ACL_RULE, rule);
}

/**
 * @tc.name: IsPermAvailableRangeSatisfied003
 * @tc.desc: Verify MDM permission passes for debug-like none distribution type.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, IsPermAvailableRangeSatisfied003, TestSize.Level0)
{
    BundleParam param = {};
    param.bundleName = "com.example.test";
    param.apiVersion = TEST_API_VERSION;
    param.distributionType = static_cast<int32_t>(Verify::AppDistType::NONE_TYPE);
    param.isDebug = true;

    PermissionBriefDef briefDef = {};
    briefDef.permissionName = const_cast<char *>("ohos.permission.MDM_TEST");
    briefDef.availableType = ATokenAvailableTypeEnum::MDM;

    PermissionRulesEnum rule = PERMISSION_ACL_RULE;
    EXPECT_TRUE(PermissionConstraintCheck::IsPermAvailableRangeSatisfied(param, briefDef, rule));
    EXPECT_EQ(PERMISSION_ACL_RULE, rule);
}

/**
 * @tc.name: AclAndEdmCheck001
 * @tc.desc: Verify acl and range check report correct permission and rule.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, AclAndEdmCheck001, TestSize.Level0)
{
    BundleParam param = {};
    param.bundleName = "com.example.test";
    param.apiVersion = TEST_API_VERSION;
    param.distributionType = static_cast<int32_t>(Verify::AppDistType::ENTERPRISE_NORMAL);

    PermissionBriefDef briefDef = {};
    briefDef.permissionName = const_cast<char *>("ohos.permission.TEST_ACL_RANGE");
    briefDef.availableLevel = APL_SYSTEM_BASIC;
    briefDef.provisionEnable = true;

    HapPolicy policy = {};
    policy.apl = APL_NORMAL;

    HapInfoCheckResult result = {};
    EXPECT_FALSE(PermissionConstraintCheck::AclAndEdmCheck(param, briefDef, policy, result));
    EXPECT_EQ(briefDef.permissionName, result.permCheckResult.permissionName);
    EXPECT_EQ(PERMISSION_ACL_RULE, result.permCheckResult.rule);
}

/**
 * @tc.name: AclAndEdmCheck002
 * @tc.desc: Verify edm failure is reported with edm rule.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, AclAndEdmCheck002, TestSize.Level0)
{
    BundleParam param = {};
    param.bundleName = "com.example.test";
    param.apiVersion = TEST_API_VERSION;
    param.distributionType = static_cast<int32_t>(Verify::AppDistType::APP_GALLERY);

    PermissionBriefDef briefDef = {};
    briefDef.permissionName = const_cast<char *>("ohos.permission.ENTERPRISE_MANAGE_SETTINGS");
    briefDef.availableType = ATokenAvailableTypeEnum::MDM;

    HapPolicy policy = {};
    policy.apl = APL_NORMAL;
    policy.aclRequestedList = {briefDef.permissionName};

    HapInfoCheckResult result = {};
    EXPECT_FALSE(PermissionConstraintCheck::AclAndEdmCheck(param, briefDef, policy, result));
    EXPECT_EQ(briefDef.permissionName, result.permCheckResult.permissionName);
    EXPECT_EQ(PERMISSION_EDM_RULE, result.permCheckResult.rule);
}

/**
 * @tc.name: IsPermAvailableRangeSatisfied004
 * @tc.desc: Verify enterprise normal permission passes for system app.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, IsPermAvailableRangeSatisfied004, TestSize.Level0)
{
    BundleParam param = {};
    param.bundleName = "com.example.test";
    param.apiVersion = TEST_API_VERSION;
    param.isSystem = true;

    PermissionBriefDef briefDef = {};
    briefDef.permissionName = const_cast<char *>("ohos.permission.ENTERPRISE_NORMAL_TEST");
    briefDef.availableType = ATokenAvailableTypeEnum::ENTERPRISE_NORMAL;

    PermissionRulesEnum rule = PERMISSION_ACL_RULE;
    EXPECT_TRUE(PermissionConstraintCheck::IsPermAvailableRangeSatisfied(param, briefDef, rule));
    EXPECT_EQ(PERMISSION_ACL_RULE, rule);
}

/**
 * @tc.name: IsPermAvailableRangeSatisfied005
 * @tc.desc: Verify enterprise normal permission passes for debug app.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, IsPermAvailableRangeSatisfied005, TestSize.Level0)
{
    BundleParam param = {};
    param.bundleName = "com.example.test";
    param.apiVersion = TEST_API_VERSION;
    param.isDebug = true;

    PermissionBriefDef briefDef = {};
    briefDef.permissionName = const_cast<char *>("ohos.permission.ENTERPRISE_NORMAL_TEST");
    briefDef.availableType = ATokenAvailableTypeEnum::ENTERPRISE_NORMAL;

    PermissionRulesEnum rule = PERMISSION_ACL_RULE;
    EXPECT_TRUE(PermissionConstraintCheck::IsPermAvailableRangeSatisfied(param, briefDef, rule));
    EXPECT_EQ(PERMISSION_ACL_RULE, rule);
}

/**
 * @tc.name: IsPermAvailableRangeSatisfied006
 * @tc.desc: Verify enterprise normal permission records reject rule for app gallery distribution.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, IsPermAvailableRangeSatisfied006, TestSize.Level0)
{
    BundleParam param = {};
    param.bundleName = "com.example.test";
    param.apiVersion = TEST_API_VERSION;
    param.distributionType = static_cast<int32_t>(Verify::AppDistType::APP_GALLERY);

    PermissionBriefDef briefDef = {};
    briefDef.permissionName = const_cast<char *>("ohos.permission.ENTERPRISE_NORMAL_TEST");
    briefDef.availableType = ATokenAvailableTypeEnum::ENTERPRISE_NORMAL;

    PermissionRulesEnum rule = PERMISSION_ACL_RULE;
    EXPECT_TRUE(PermissionConstraintCheck::IsPermAvailableRangeSatisfied(param, briefDef, rule));
    EXPECT_EQ(PERMISSION_ENTERPRISE_NORMAL_RULE, rule);
}

/**
 * @tc.name: FixBriefPermData001
 * @tc.desc: PermissionConstraintCheck::FixBriefPermData filters unexpected permissions and appends missing ones.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, FixBriefPermData001, TestSize.Level0)
{
    uint32_t cameraCode = 0;
    uint32_t micCode = 0;
    uint32_t bluetoothCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", cameraCode));
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.MICROPHONE", micCode));
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.USE_BLUETOOTH", bluetoothCode));

    std::vector<BriefPermData> data;
    BriefPermData cameraData = {0};
    cameraData.permCode = static_cast<uint16_t>(cameraCode);
    cameraData.status = PERMISSION_GRANTED;
    cameraData.flag = PERMISSION_SYSTEM_FIXED;
    data.emplace_back(cameraData);

    BriefPermData micData = {0};
    micData.permCode = static_cast<uint16_t>(micCode);
    micData.status = PERMISSION_GRANTED;
    micData.flag = PERMISSION_USER_SET;
    data.emplace_back(micData);

    BundleInfoInner infoInner;
    infoInner.permCodeList = {static_cast<uint16_t>(cameraCode), static_cast<uint16_t>(bluetoothCode)};

    bool isFixed = false;
    PermissionConstraintCheck::FixBriefPermData(infoInner, DLP_COMMON, data, isFixed);

    ASSERT_EQ(2u, data.size());
    EXPECT_TRUE(isFixed);
    EXPECT_EQ(static_cast<uint16_t>(cameraCode), data[0].permCode);
    EXPECT_EQ(PERMISSION_GRANTED, data[0].status);
    EXPECT_EQ(PERMISSION_SYSTEM_FIXED, data[0].flag);

    EXPECT_EQ(static_cast<uint16_t>(bluetoothCode), data[1].permCode);
    EXPECT_EQ(PERMISSION_GRANTED, data[1].status);
    EXPECT_EQ(PERMISSION_SYSTEM_FIXED, data[1].flag);
}

/**
 * @tc.name: FixBriefPermData002
 * @tc.desc: Verify missing grant permission is initialized with default deny flag.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, FixBriefPermData002, TestSize.Level0)
{
    uint32_t cameraCode = 0;
    uint32_t bluetoothCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", cameraCode));
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.USE_BLUETOOTH", bluetoothCode));

    std::vector<BriefPermData> data;
    BundleInfoInner infoInner;
    infoInner.permCodeList = {static_cast<uint16_t>(cameraCode), static_cast<uint16_t>(bluetoothCode)};

    bool isFixed = false;
    PermissionConstraintCheck::FixBriefPermData(infoInner, DLP_COMMON, data, isFixed);

    ASSERT_EQ(2u, data.size());
    EXPECT_TRUE(isFixed);
    EXPECT_EQ(static_cast<uint16_t>(cameraCode), data[0].permCode);
    EXPECT_EQ(PERMISSION_DENIED, data[0].status);
    EXPECT_EQ(PERMISSION_DEFAULT_FLAG, data[0].flag);
    EXPECT_EQ(static_cast<uint16_t>(bluetoothCode), data[1].permCode);
    EXPECT_EQ(PERMISSION_GRANTED, data[1].status);
    EXPECT_EQ(PERMISSION_SYSTEM_FIXED, data[1].flag);
}

/**
 * @tc.name: FixBriefPermData003
 * @tc.desc: Verify DLP filtering removes permissions unavailable to current dlp type.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, FixBriefPermData003, TestSize.Level0)
{
    auto& manager = DlpPermissionSetManager::GetInstance();
    manager.dlpPermissionModeMap_.clear();

    PermissionDlpMode dlpInfo;
    dlpInfo.permissionName = "ohos.permission.CAMERA";
    dlpInfo.dlpMode = DLP_PERM_FULL_CONTROL;
    manager.ProcessDlpPermInfos({dlpInfo});

    uint32_t cameraCode = 0;
    uint32_t microphoneCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.CAMERA", cameraCode));
    ASSERT_TRUE(TransferPermissionToOpcode("ohos.permission.MICROPHONE", microphoneCode));

    std::vector<BriefPermData> data;
    BundleInfoInner infoInner;
    infoInner.permCodeList = {static_cast<uint16_t>(cameraCode), static_cast<uint16_t>(microphoneCode)};

    bool isFixed = false;
    PermissionConstraintCheck::FixBriefPermData(infoInner, DLP_READ, data, isFixed);

    ASSERT_EQ(1u, data.size());
    EXPECT_TRUE(isFixed);
    EXPECT_EQ(static_cast<uint16_t>(microphoneCode), data[0].permCode);
    manager.dlpPermissionModeMap_.clear();
}

/**
 * @tc.name: FixPersistentHapInfo001
 * @tc.desc: Verify FixPersistentHapInfo updates mismatched basic fields.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, FixPersistentHapInfo001, TestSize.Level0)
{
    BundleParam param;
    param.bundleName = "com.example.test";
    param.apiVersion = TEST_API_VERSION;
    param.isSystem = true;
    param.isAtomicService = false;
    param.isDebug = false;

    HapPolicy policy;
    policy.apl = APL_SYSTEM_CORE;

    HapTokenInfoItem hapTokenInfoItem;
    hapTokenInfoItem.bundleName = "com.example.old";
    hapTokenInfoItem.apiVersion = OLD_API_VERSION;
    hapTokenInfoItem.apl = APL_NORMAL;
    hapTokenInfoItem.tokenAttr = 0;

    bool isFixed = false;
    PermissionConstraintCheck::FixPersistentHapInfo(param, policy, hapTokenInfoItem, isFixed);

    EXPECT_TRUE(isFixed);
    EXPECT_EQ("com.example.test", hapTokenInfoItem.bundleName);
    EXPECT_EQ(TEST_API_VERSION, hapTokenInfoItem.apiVersion);
    EXPECT_EQ(APL_SYSTEM_CORE, hapTokenInfoItem.apl);
    EXPECT_TRUE((hapTokenInfoItem.tokenAttr & SYSTEM_APP_FLAG) != 0);
}

/**
 * @tc.name: FixPersistentHapInfo002
 * @tc.desc: Verify FixPersistentHapInfo updates tokenAttr flags correctly.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, FixPersistentHapInfo002, TestSize.Level0)
{
    BundleParam param;
    param.bundleName = "com.example.test";
    param.isSystem = false;
    param.isAtomicService = true;
    param.isDebug = true;

    HapPolicy policy;
    policy.apl = APL_NORMAL;

    HapTokenInfoItem hapTokenInfoItem;
    hapTokenInfoItem.bundleName = "com.example.test";
    hapTokenInfoItem.tokenAttr = SYSTEM_APP_FLAG;

    bool isFixed = false;
    PermissionConstraintCheck::FixPersistentHapInfo(param, policy, hapTokenInfoItem, isFixed);

    EXPECT_TRUE(isFixed);
    EXPECT_FALSE((hapTokenInfoItem.tokenAttr & SYSTEM_APP_FLAG) != 0);
    EXPECT_TRUE((hapTokenInfoItem.tokenAttr & ATOMIC_SERVICE_FLAG) != 0);
    EXPECT_TRUE((hapTokenInfoItem.tokenAttr & DEBUG_APP_FLAG) != 0);
}

/**
 * @tc.name: FixPersistentHapInfo003
 * @tc.desc: Verify FixPersistentHapInfo does not modify matching fields.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, FixPersistentHapInfo003, TestSize.Level0)
{
    BundleParam param;
    param.bundleName = "com.example.test";
    param.appId = "com.example.test.app";
    param.apiVersion = TEST_API_VERSION;
    param.isSystem = true;
    param.isAtomicService = false;
    param.isDebug = false;

    HapPolicy policy;
    policy.apl = APL_SYSTEM_BASIC;

    HapTokenInfoItem hapTokenInfoItem;
    hapTokenInfoItem.bundleName = "com.example.test";
    hapTokenInfoItem.appId = "com.example.test.app";
    hapTokenInfoItem.apiVersion = TEST_API_VERSION;
    hapTokenInfoItem.apl = APL_SYSTEM_BASIC;
    hapTokenInfoItem.tokenAttr = SYSTEM_APP_FLAG;

    bool isFixed = false;
    PermissionConstraintCheck::FixPersistentHapInfo(param, policy, hapTokenInfoItem, isFixed);

    EXPECT_FALSE(isFixed);
    EXPECT_EQ("com.example.test", hapTokenInfoItem.bundleName);
    EXPECT_EQ("com.example.test.app", hapTokenInfoItem.appId);
    EXPECT_EQ(TEST_API_VERSION, hapTokenInfoItem.apiVersion);
    EXPECT_EQ(APL_SYSTEM_BASIC, hapTokenInfoItem.apl);
    EXPECT_TRUE((hapTokenInfoItem.tokenAttr & SYSTEM_APP_FLAG) != 0);
}

/**
 * @tc.name: BuildIdType001
 * @tc.desc: PermissionConstraintCheck::BuildIdType function test.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, BuildIdType001, TestSize.Level0)
{
    BundleParam param;
    HapPolicy policy;

    param.isDebug = true;
    EXPECT_EQ(DEBUG_ID_TYPE, PermissionConstraintCheck::BuildIdType(param, policy));

    param.isDebug = false;
    param.appIdentifier = APP_IDENTIFIER_ZERO;
    EXPECT_EQ(BASE_APP_ID_TYPE, PermissionConstraintCheck::BuildIdType(param, policy));

    param.appIdentifier = APP_IDENTIFIER_ONE;
    PermissionStatus tempJitAllow;
    tempJitAllow.permissionName = "TEMPJITALLOW";
    policy.permStateList = { tempJitAllow };
    EXPECT_EQ(JIT_GRANTED_ID_TYPE, PermissionConstraintCheck::BuildIdType(param, policy));

    policy.permStateList.clear();
    EXPECT_EQ(DEFAULT_ID_TYPE, PermissionConstraintCheck::BuildIdType(param, policy));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

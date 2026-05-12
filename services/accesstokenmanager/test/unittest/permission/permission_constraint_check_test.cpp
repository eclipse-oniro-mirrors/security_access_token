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

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {

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
    param.apiVersion = 12;
    param.distributionType = Verify::AppDistType::ENTERPRISE_NORMAL;

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
    param.apiVersion = 12;
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
    param.apiVersion = 12;
    param.distributionType = Verify::AppDistType::NONE_TYPE;
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
    param.apiVersion = 12;
    param.distributionType = Verify::AppDistType::ENTERPRISE_NORMAL;

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
    param.apiVersion = 12;
    param.distributionType = Verify::AppDistType::APP_GALLERY;

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
    param.apiVersion = 12;
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
    param.apiVersion = 12;
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
    param.apiVersion = 12;
    param.distributionType = Verify::AppDistType::APP_GALLERY;

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
 * @tc.name: BuildIdType001
 * @tc.desc: PermissionConstraintCheck::BuildIdType function test.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionConstraintCheckTest, BuildIdType001, TestSize.Level0)
{
    BundleParam param;
    HapPolicy policy;

    param.isDebug = true;
    EXPECT_EQ(3, PermissionConstraintCheck::BuildIdType(param, policy));

    param.isDebug = false;
    param.appIdentifier = 0;
    EXPECT_EQ(5, PermissionConstraintCheck::BuildIdType(param, policy));

    param.appIdentifier = 1;
    PermissionStatus tempJitAllow;
    tempJitAllow.permissionName = "TEMPJITALLOW";
    policy.permStateList = { tempJitAllow };
    EXPECT_EQ(10, PermissionConstraintCheck::BuildIdType(param, policy));

    policy.permStateList.clear();
    EXPECT_EQ(2, PermissionConstraintCheck::BuildIdType(param, policy));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

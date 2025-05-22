/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <memory>
#include <string>
#include "accesstoken_info_manager.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private

#define private public
#include "json_parse_loader.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
class PrivacyParcelTest : public testing::Test  {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp();
    void TearDown();

public:
    std::shared_ptr<AccessTokenManagerService> atManagerService_;
};

void PrivacyParcelTest::SetUpTestCase()
{
    // delete all test 0x28100000 - 0x28100007
    for (unsigned int i = 0x28100000; i <= 0x28100007; i++) {
        AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(i);
    }
}
void PrivacyParcelTest::TearDownTestCase() {}
void PrivacyParcelTest::SetUp()
{
    atManagerService_ = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    EXPECT_NE(nullptr, atManagerService_);
}
void PrivacyParcelTest::TearDown() {}

/*
 * @tc.name: IsDirExsit001
 * @tc.desc: IsDirExsit input param error
 * @tc.type: FUNC
 * @tc.require: issueI6024A
 */
HWTEST_F(JsonParseTest, IsDirExsit001, TestSize.Level0)
{
    ConfigPolicLoader loader;
    EXPECT_FALSE(loader.IsDirExsit(""));
    int32_t fd = open(TEST_JSON_PATH.c_str(), O_RDWR | O_CREAT);
    EXPECT_NE(-1, fd);

    EXPECT_FALSE(loader.IIsDirExsit(TEST_JSON_PATH.c_str()));
}

/**
 * @tc.name: ParserNativeRawData001
 * @tc.desc: Verify processing right native token json.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(JsonParseTest, ParserNativeRawData001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "test ParserNativeRawData001!");
    std::string testStr = R"([)"\
        R"({"processName":"process6","APL":3,"version":1,"tokenId":685266937,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"], "permissions":[], "nativeAcls":[]},)"\
        R"({"processName":"process5","APL":3,"version":1,"tokenId":678065606,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"], "permissions":[], "nativeAcls":[]}])";

    ConfigPolicLoader loader;
    std::vector<NativeTokenInfoBase> tokenInfos;
    loader.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(2), tokenInfos.size());

    ASSERT_EQ("process6", tokenInfos[0].processName);
    ASSERT_EQ(static_cast<AccessTokenID>(685266937), tokenInfos[0].tokenID);

    ASSERT_EQ("process5", tokenInfos[1].processName);
    ASSERT_EQ(static_cast<AccessTokenID>(678065606), tokenInfos[1].tokenID);
}

/**
 * @tc.name: ParserNativeRawData002
 * @tc.desc: Verify processing wrong native token json.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(JsonParseTest, ParserNativeRawData002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "test ParserNativeRawData002!");
    std::string testStr = R"([{"processName":""}])";
    std::vector<NativeTokenInfoBase> tokenInfos;

    ConfigPolicLoader loader;
    loader.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr1 = R"([{"processName":"", }])";
    loader.ParserNativeRawData(testStr1, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr2 = R"([{"processName":"process6"}, {}])";
    loader.ParserNativeRawData(testStr2, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr3 = R"([{"processName":""}, {"":"", ""}])";
    loader.ParserNativeRawData(testStr3, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr4 = R"([{"processName":"process6", "tokenId":685266937, "APL":3, "version":new}])";
    loader.ParserNativeRawData(testStr4, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr5 = R"([{"processName":"process6", "tokenId":685266937, "APL":7, "version":1}])";
    loader.ParserNativeRawData(testStr5, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr6 =
        R"({"NativeToken":[{"processName":"process6", "tokenId":685266937, "APL":7, "version":1}]})";
    loader.ParserNativeRawData(testStr6, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr7 = R"({"NativeToken":[{"processName":"process6", "tokenId":685266937, "APL":7, "version":1}])";
    loader.ParserNativeRawData(testStr7, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr8 = R"(["NativeToken":])";
    loader.ParserNativeRawData(testStr8, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr9 = R"([)";
    loader.ParserNativeRawData(testStr9, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());
}

/**
 * @tc.name: ParserNativeRawData003
 * @tc.desc: Verify from json right case.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(JsonParseTest, ParserNativeRawData003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "test ParserNativeRawData003!");
    std::string testStr = R"([)"\
        R"({"processName":"process6","APL":APL_SYSTEM_CORE,"version":1,"tokenId":685266937,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"],)"\
        R"("permissions":["ohos.permission.PLACE_CALL"],)"\
        R"("nativeAcls":["ohos.permission.PLACE_CALL"]})"\
        R"(])";
    ConfigPolicLoader loader;
    std::vector<NativeTokenInfoBase> tokenInfos;
    loader.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(1), tokenInfos.size());
    ASSERT_EQ(native.tokenID, 685266937);
}

/**
 * @tc.name: ParserNativeRawData004
 * @tc.desc: Verify from json wrong case.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(JsonParseTest, ParserNativeRawData004, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "test ParserNativeRawData004!");
    // version wrong
    std::string testStr = R"([)"\
        R"({"processName":"process6","APL":APL_SYSTEM_CORE,"version":2,"tokenId":685266937,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]})"\
        R"(])";
    ConfigPolicLoader loader;
    std::vector<NativeTokenInfoBase> tokenInfos;
    loader.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    // APL wrong
    testStr = R"([)"\
        R"({"processName":"process6","APL":-1,"version":1,"tokenId":685266937,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]})"\
        R"(])";
    loader.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    // tokenId wrong
    testStr = R"([)"\
        R"({"processName":"process6","APL":APL_SYSTEM_BASIC,"version":1,"tokenId":0,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]})"\
        R"(])";
    loader.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    // process name empty
    testStr = R"([)"\
        R"({"processName":"","APL":APL_SYSTEM_BASIC,"version":1,"tokenId":685266937,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]})"\
        R"(])";
    loader.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    // process name too long
    std::string name(512, 'c');
    testStr = R"([)"\
        R"({"processName":name,"APL":APL_SYSTEM_BASIC,"version":1,"tokenId":685266937,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]})"\
        R"(])";
    loader.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    // lose process name
    testStr = R"([)"\
        R"({"APL":APL_SYSTEM_BASIC,"version":1,"tokenId":685266937,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]})"\
        R"(])";
    loader.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());
}

/**
 * @tc.name: init001
 * @tc.desc: test get native cfg
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(JsonParseTest, init001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "test init001!");

    const char *dcaps[1];
    dcaps[0] = "AT_CAP_01";
    int dcapNum = 1;
    const char *perms[2];
    perms[0] = "ohos.permission.test1";
    perms[1] = "ohos.permission.test2";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = dcapNum,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = dcaps,
        .perms = perms,
        .acls = nullptr,
        .processName = "native_token_test7",
        .aplStr = "system_core",
    };
    uint64_t tokenId = ::GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, INVALID_TOKENID);

    atManagerService_->ReloadNativeTokenInfo();

    NativeTokenInfoBase findInfo;
    int ret = AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(tokenId, findInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(findInfo.processName, infoInstance.processName);

    ret = AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(tokenId);
    ASSERT_EQ(ret, RET_SUCCESS);
}

#ifdef SUPPORT_SANDBOX_APP
static void PrepareJsonData1()
{
    std::string testStr = R"({"dlpPermissions":[)"\
        R"({"name":"ohos.permission.CAPTURE_SCREEN","dlpGrantRange":"none"},)"\
        R"({"name":"ohos.permission.CHANGE_ABILITY_ENABLED_STATE","dlpGrantRange":"all"},)"\
        R"({"name":"ohos.permission.CLEAN_APPLICATION_DATA","dlpGrantRange":"full_control"}]})";

    ConfigPolicLoader loader;
    std::vector<PermissionDlpMode> dlpPerms;
    loader.ParserDlpPermsRawData(testStr, permDefList);
    for (auto iter = dlpPerms.begin(); iter != dlpPerms.end(); iter++) {
        GTEST_LOG_(INFO) << "iter:" << iter->permissionName.c_str();
    }
    DlpPermissionSetManager::GetInstance().ProcessDlpPermInfos(dlpPerms);
}

/**
 * @tc.name: DlpPermissionConfig001
 * @tc.desc: test DLP_COMMON app with system_grant permissions.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGR
 */
HWTEST_F(PermissionManagerTest, DlpPermissionConfig001, TestSize.Level0)
{
    PrepareJsonData1();

    g_infoManagerTestStateA.permissionName = "ohos.permission.CAPTURE_SCREEN";
    g_infoManagerTestStateB.permissionName = "ohos.permission.CHANGE_ABILITY_ENABLED_STATE";
    g_infoManagerTestStateC.permissionName = "ohos.permission.CLEAN_APPLICATION_DATA";
    g_infoManagerTestStateD.permissionName = "ohos.permission.COMMONEVENT_STICKY";

    static HapPolicy infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain1",
        .permList = {},
        .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB,
                          g_infoManagerTestStateC, g_infoManagerTestStateD}
    };
    static HapInfoParams infoManagerTestInfoParms = {
        .userID = 1,
        .bundleName = "DlpPermissionConfig001",
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "DlpPermissionConfig001"
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoManagerTestInfoParms,
        infoManagerTestPolicyPrams, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.COMMONEVENT_STICKY");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CAPTURE_SCREEN");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CHANGE_ABILITY_ENABLED_STATE");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CLEAN_APPLICATION_DATA");
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: DlpPermissionConfig002
 * @tc.desc: test DLP_READ app with system_grant permissions.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGR
 */
HWTEST_F(PermissionManagerTest, DlpPermissionConfig002, TestSize.Level0)
{
    PrepareJsonData1();

    g_infoManagerTestStateA.permissionName = "ohos.permission.CAPTURE_SCREEN";
    g_infoManagerTestStateB.permissionName = "ohos.permission.CHANGE_ABILITY_ENABLED_STATE";
    g_infoManagerTestStateC.permissionName = "ohos.permission.CLEAN_APPLICATION_DATA";
    g_infoManagerTestStateD.permissionName = "ohos.permission.COMMONEVENT_STICKY";

    static HapPolicy infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain2",
        .permList = {},
        .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB,
                          g_infoManagerTestStateC, g_infoManagerTestStateD}
    };
    static HapInfoParams infoManagerTestInfoParms = {
        .userID = 1,
        .bundleName = "DlpPermissionConfig002",
        .instIndex = 0,
        .dlpType = DLP_READ,
        .appIDDesc = "DlpPermissionConfig002"
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoManagerTestInfoParms,
        infoManagerTestPolicyPrams, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CAPTURE_SCREEN");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.COMMONEVENT_STICKY");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CHANGE_ABILITY_ENABLED_STATE");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CLEAN_APPLICATION_DATA");
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: DlpPermissionConfig003
 * @tc.desc: test DLP_FULL_CONTROL app with system_grant permissions.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGR
 */
HWTEST_F(PermissionManagerTest, DlpPermissionConfig003, TestSize.Level0)
{
    PrepareJsonData1();

    g_infoManagerTestStateA.permissionName = "ohos.permission.CAPTURE_SCREEN";
    g_infoManagerTestStateB.permissionName = "ohos.permission.CHANGE_ABILITY_ENABLED_STATE";
    g_infoManagerTestStateC.permissionName = "ohos.permission.CLEAN_APPLICATION_DATA";
    g_infoManagerTestStateD.permissionName = "ohos.permission.COMMONEVENT_STICKY";

    static HapPolicy infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain3",
        .permList = {},
        .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB,
                          g_infoManagerTestStateC, g_infoManagerTestStateD}
    };
    static HapInfoParams infoManagerTestInfoParms = {
        .userID = 1,
        .bundleName = "DlpPermissionConfig003",
        .instIndex = 0,
        .dlpType = DLP_FULL_CONTROL,
        .appIDDesc = "DlpPermissionConfig003"
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoManagerTestInfoParms,
        infoManagerTestPolicyPrams, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CLEAN_APPLICATION_DATA");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.COMMONEVENT_STICKY");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CAPTURE_SCREEN");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CHANGE_ABILITY_ENABLED_STATE");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

static void PrepareUserPermState()
{
    g_infoManagerTestStateA.permissionName = "ohos.permission.MEDIA_LOCATION";
    g_infoManagerTestStateA.grantStatus = PERMISSION_DENIED;
    g_infoManagerTestStateB.permissionName = "ohos.permission.MICROPHONE";
    g_infoManagerTestStateB.grantStatus = PERMISSION_DENIED;
    g_infoManagerTestStateC.permissionName = "ohos.permission.READ_CALENDAR";
    g_infoManagerTestStateC.grantStatus = PERMISSION_DENIED;
    g_infoManagerTestStateD.permissionName = "ohos.permission.READ_CALL_LOG";
    g_infoManagerTestStateD.grantStatus = PERMISSION_DENIED;
}

static void PrepareJsonData2()
{
    std::string testStr = R"({"dlpPermissions":[)"\
        R"({"name":"ohos.permission.MEDIA_LOCATION","dlpGrantRange":"none"},)"\
        R"({"name":"ohos.permission.MICROPHONE","dlpGrantRange":"all"},)"\
        R"({"name":"ohos.permission.READ_CALENDAR","dlpGrantRange":"full_control"}]})";

    ConfigPolicLoader loader;
    std::vector<PermissionDlpMode> dlpPerms;
    if (!loader.ParserDlpPermsRawData(testStr, permDefList)) {
        GTEST_LOG_(INFO) << "ParserDlpPermsRawData failed.";
    }
    DlpPermissionSetManager::GetInstance().ProcessDlpPermInfos(dlpPermissions);
}

/**
 * @tc.name: DlpPermissionConfig004
 * @tc.desc: test DLP_COMMON app with user_grant permissions.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGR
 */
HWTEST_F(PermissionManagerTest, DlpPermissionConfig004, TestSize.Level0)
{
    PrepareJsonData2();
    PrepareUserPermState();

    static HapPolicy infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain4",
        .permList = {g_infoManagerPermDef1, g_infoManagerPermDef2,
                     g_infoManagerPermDef3, g_infoManagerPermDef4},
        .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB,
                          g_infoManagerTestStateC, g_infoManagerTestStateD}
    };
    static HapInfoParams infoManagerTestInfoParms = {
        .userID = 1,
        .bundleName = "DlpPermissionConfig004",
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "DlpPermissionConfig004"
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoManagerTestInfoParms,
        infoManagerTestPolicyPrams, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MEDIA_LOCATION", PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.READ_CALENDAR", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.READ_CALL_LOG", PERMISSION_USER_FIXED);

    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MEDIA_LOCATION");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.READ_CALENDAR");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.READ_CALL_LOG");
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: DlpPermissionConfig005
 * @tc.desc: test DLP_READ app with user_grant permissions.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGR
 */
HWTEST_F(PermissionManagerTest, DlpPermissionConfig005, TestSize.Level0)
{
    PrepareJsonData2();
    PrepareUserPermState();

    static HapPolicy infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain5",
        .permList = {g_infoManagerPermDef1, g_infoManagerPermDef2,
                     g_infoManagerPermDef3, g_infoManagerPermDef4},
        .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB,
                          g_infoManagerTestStateC, g_infoManagerTestStateD}
    };
    static HapInfoParams infoManagerTestInfoParms = {
        .userID = 1,
        .bundleName = "DlpPermissionConfig005",
        .instIndex = 0,
        .dlpType = DLP_READ,
        .appIDDesc = "DlpPermissionConfig005"
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoManagerTestInfoParms,
        infoManagerTestPolicyPrams, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.READ_CALENDAR", PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.READ_CALL_LOG", PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MEDIA_LOCATION", PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);

    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.READ_CALENDAR");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.READ_CALL_LOG");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MEDIA_LOCATION");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE");
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: DlpPermissionConfig006
 * @tc.desc: test DLP_FULL_CONTROL app with user_grant permissions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionManagerTest, DlpPermissionConfig006, TestSize.Level0)
{
    PrepareJsonData2();
    PrepareUserPermState();

    static HapPolicy infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain6",
        .permList = {g_infoManagerPermDef1, g_infoManagerPermDef2,
                     g_infoManagerPermDef3, g_infoManagerPermDef4},
        .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB,
                          g_infoManagerTestStateC, g_infoManagerTestStateD}
    };
    static HapInfoParams infoManagerTestInfoParms = {
        .userID = 1,
        .bundleName = "DlpPermissionConfig006",
        .instIndex = 0,
        .dlpType = DLP_FULL_CONTROL,
        .appIDDesc = "DlpPermissionConfig006"
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoManagerTestInfoParms,
        infoManagerTestPolicyPrams, tokenIdEx, undefValues);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.READ_CALENDAR", PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MEDIA_LOCATION", PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.READ_CALL_LOG", PERMISSION_USER_FIXED);

    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.READ_CALENDAR");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MEDIA_LOCATION");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.READ_CALL_LOG");
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

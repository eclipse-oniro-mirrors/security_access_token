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

#include "accesstoken_kit.h"
#include "table_item.h"
#include "token_field_const.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
constexpr uint32_t SYSTEM_APP_FLAG = 0x0001;
constexpr uint32_t DEBUG_APP_FLAG = 0x0008;

class TableItemTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: HapTokenInfoItemBuildAddValue001
 * @tc.desc: Verify HapTokenInfoItem::BuildAddValue generates correct GenericValues.
 * @tc.type: FUNC
 */
HWTEST_F(TableItemTest, HapTokenInfoItemBuildAddValue001, TestSize.Level0)
{
    HapTokenInfoItem item;
    item.tokenId = 0x12345678;
    item.userId = 100;
    item.bundleName = "com.example.test";
    item.instIndex = 0;
    item.dlpType = DLP_COMMON;
    item.appId = "com.example.test.app";
    item.deviceId = "test-device-001";
    item.apl = APL_SYSTEM_CORE;
    item.version = 1;
    item.tokenAttr = SYSTEM_APP_FLAG;
    item.apiVersion = 12;
    item.permDialogCapState = true;
    item.uid = 20100000;
    item.migrated = true;
    item.reserved = ReservedType::NONE;

    std::vector<GenericValues> addValues;
    item.BuildAddValue(addValues);

    ASSERT_EQ(1u, addValues.size());
    const auto& value = addValues[0];

    EXPECT_EQ(static_cast<int32_t>(0x12345678), value.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
    EXPECT_EQ(100, value.GetInt(TokenFiledConst::FIELD_USER_ID));
    EXPECT_EQ("com.example.test", value.GetString(TokenFiledConst::FIELD_BUNDLE_NAME));
    EXPECT_EQ(0, value.GetInt(TokenFiledConst::FIELD_INST_INDEX));
    EXPECT_EQ(static_cast<int32_t>(DLP_COMMON), value.GetInt(TokenFiledConst::FIELD_DLP_TYPE));
    EXPECT_EQ("com.example.test.app", value.GetString(TokenFiledConst::FIELD_APP_ID));
    EXPECT_EQ("test-device-001", value.GetString(TokenFiledConst::FIELD_DEVICE_ID));
    EXPECT_EQ(static_cast<int32_t>(APL_SYSTEM_CORE), value.GetInt(TokenFiledConst::FIELD_APL));
    EXPECT_EQ(1, value.GetInt(TokenFiledConst::FIELD_TOKEN_VERSION));
    EXPECT_EQ(static_cast<int32_t>(SYSTEM_APP_FLAG), value.GetInt(TokenFiledConst::FIELD_TOKEN_ATTR));
    EXPECT_EQ(12, value.GetInt(TokenFiledConst::FIELD_API_VERSION));
    EXPECT_NE(0, value.GetInt(TokenFiledConst::FIELD_FORBID_PERM_DIALOG));
    EXPECT_EQ(20100000, value.GetInt(TokenFiledConst::FIELD_UID));
    EXPECT_NE(0, value.GetInt(TokenFiledConst::FIELD_MIGRATED));
    EXPECT_EQ(static_cast<int32_t>(ReservedType::NONE), value.GetInt(TokenFiledConst::FIELD_RESERVED));
}

/**
 * @tc.name: HapTokenInfoItemBuildDeleteValues001
 * @tc.desc: Verify HapTokenInfoItem::BuildDeleteValues generates correct GenericValues.
 * @tc.type: FUNC
 */
HWTEST_F(TableItemTest, HapTokenInfoItemBuildDeleteValues001, TestSize.Level0)
{
    HapTokenInfoItem item;
    item.tokenId = 0x87654321;

    GenericValues deleteValue;
    item.BuildDeleteValues(deleteValue);

    EXPECT_EQ(static_cast<int32_t>(0x87654321), deleteValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
}

/**
 * @tc.name: HapTokenInfoItemBuildFindValues001
 * @tc.desc: Verify HapTokenInfoItem::BuildFindValues generates correct GenericValues.
 * @tc.type: FUNC
 */
HWTEST_F(TableItemTest, HapTokenInfoItemBuildFindValues001, TestSize.Level0)
{
    HapTokenInfoItem item;
    item.tokenId = 0xABCDEF01;

    GenericValues findValue;
    item.BuildFindValues(findValue);

    EXPECT_EQ(static_cast<int32_t>(0xABCDEF01), findValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
}

/**
 * @tc.name: HapTokenInfoItemBuildUpdateValues001
 * @tc.desc: Verify HapTokenInfoItem::BuildUpdateValues generates correct delete and add values.
 * @tc.type: FUNC
 */
HWTEST_F(TableItemTest, HapTokenInfoItemBuildUpdateValues001, TestSize.Level0)
{
    HapTokenInfoItem item;
    item.tokenId = 0x12345678;
    item.bundleName = "com.example.update";

    GenericValues deleteValue;
    std::vector<GenericValues> addValues;
    item.BuildUpdateValues(deleteValue, addValues);

    EXPECT_EQ(static_cast<int32_t>(0x12345678), deleteValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
    ASSERT_EQ(1u, addValues.size());
    EXPECT_EQ("com.example.update", addValues[0].GetString(TokenFiledConst::FIELD_BUNDLE_NAME));
}

/**
 * @tc.name: HapTokenInfoItemLoadFromDB001
 * @tc.desc: Verify HapTokenInfoItem::LoadFromDB correctly loads items from GenericValues.
 * @tc.type: FUNC
 */
HWTEST_F(TableItemTest, HapTokenInfoItemLoadFromDB001, TestSize.Level0)
{
    std::vector<GenericValues> values;
    GenericValues value1;
    value1.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(0x11111111));
    value1.Put(TokenFiledConst::FIELD_USER_ID, static_cast<int32_t>(100));
    value1.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "com.example.one");
    value1.Put(TokenFiledConst::FIELD_INST_INDEX, static_cast<int32_t>(0));
    value1.Put(TokenFiledConst::FIELD_DLP_TYPE, static_cast<int32_t>(DLP_COMMON));
    value1.Put(TokenFiledConst::FIELD_APP_ID, "com.example.one.app");
    value1.Put(TokenFiledConst::FIELD_DEVICE_ID, "device-001");
    value1.Put(TokenFiledConst::FIELD_APL, static_cast<int32_t>(APL_NORMAL));
    value1.Put(TokenFiledConst::FIELD_TOKEN_VERSION, static_cast<int32_t>(1));
    value1.Put(TokenFiledConst::FIELD_TOKEN_ATTR, static_cast<int32_t>(SYSTEM_APP_FLAG));
    value1.Put(TokenFiledConst::FIELD_API_VERSION, 11);
    value1.Put(TokenFiledConst::FIELD_FORBID_PERM_DIALOG, static_cast<int32_t>(0));
    value1.Put(TokenFiledConst::FIELD_UID, static_cast<int32_t>(20100100));
    value1.Put(TokenFiledConst::FIELD_MIGRATED, static_cast<int32_t>(1));
    value1.Put(TokenFiledConst::FIELD_RESERVED, static_cast<int32_t>(ReservedType::NONE));
    values.emplace_back(value1);

    std::vector<HapTokenInfoItem> items;
    HapTokenInfoItem::LoadFromDB(values, items);

    ASSERT_EQ(1u, items.size());
    EXPECT_EQ(static_cast<AccessTokenID>(0x11111111), items[0].tokenId);
    EXPECT_EQ(100u, items[0].userId);
    EXPECT_EQ("com.example.one", items[0].bundleName);
    EXPECT_EQ(0u, items[0].instIndex);
    EXPECT_EQ(DLP_COMMON, items[0].dlpType);
    EXPECT_EQ("com.example.one.app", items[0].appId);
    EXPECT_EQ("device-001", items[0].deviceId);
    EXPECT_EQ(APL_NORMAL, items[0].apl);
    EXPECT_EQ(1u, items[0].version);
    EXPECT_EQ(SYSTEM_APP_FLAG, items[0].tokenAttr);
    EXPECT_EQ(11, items[0].apiVersion);
    EXPECT_FALSE(items[0].permDialogCapState);
    EXPECT_EQ(20100100u, items[0].uid);
    EXPECT_TRUE(items[0].migrated);
    EXPECT_EQ(ReservedType::NONE, items[0].reserved);
}

/**
 * @tc.name: HapTokenInfoItemLoadFromDB002
 * @tc.desc: Verify HapTokenInfoItem::LoadFromDB correctly loads multiple items.
 * @tc.type: FUNC
 */
HWTEST_F(TableItemTest, HapTokenInfoItemLoadFromDB002, TestSize.Level0)
{
    std::vector<GenericValues> values;

    GenericValues value1;
    value1.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(0x11111111));
    value1.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "com.example.one");
    value1.Put(TokenFiledConst::FIELD_USER_ID, static_cast<int32_t>(100));
    value1.Put(TokenFiledConst::FIELD_INST_INDEX, static_cast<int32_t>(0));
    value1.Put(TokenFiledConst::FIELD_DLP_TYPE, static_cast<int32_t>(DLP_COMMON));
    value1.Put(TokenFiledConst::FIELD_APP_ID, "app1");
    value1.Put(TokenFiledConst::FIELD_DEVICE_ID, "device1");
    value1.Put(TokenFiledConst::FIELD_APL, static_cast<int32_t>(APL_NORMAL));
    value1.Put(TokenFiledConst::FIELD_TOKEN_VERSION, static_cast<int32_t>(1));
    value1.Put(TokenFiledConst::FIELD_TOKEN_ATTR, static_cast<int32_t>(0));
    value1.Put(TokenFiledConst::FIELD_API_VERSION, 9);
    value1.Put(TokenFiledConst::FIELD_FORBID_PERM_DIALOG, static_cast<int32_t>(0));
    value1.Put(TokenFiledConst::FIELD_UID, static_cast<int32_t>(20100100));
    value1.Put(TokenFiledConst::FIELD_MIGRATED, static_cast<int32_t>(0));
    value1.Put(TokenFiledConst::FIELD_RESERVED, static_cast<int32_t>(ReservedType::NONE));
    values.emplace_back(value1);

    GenericValues value2;
    value2.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(0x22222222));
    value2.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "com.example.two");
    value2.Put(TokenFiledConst::FIELD_USER_ID, static_cast<int32_t>(101));
    value2.Put(TokenFiledConst::FIELD_INST_INDEX, static_cast<int32_t>(1));
    value2.Put(TokenFiledConst::FIELD_DLP_TYPE, static_cast<int32_t>(DLP_READ));
    value2.Put(TokenFiledConst::FIELD_APP_ID, "app2");
    value2.Put(TokenFiledConst::FIELD_DEVICE_ID, "device2");
    value2.Put(TokenFiledConst::FIELD_APL, static_cast<int32_t>(APL_SYSTEM_CORE));
    value2.Put(TokenFiledConst::FIELD_TOKEN_VERSION, static_cast<int32_t>(2));
    value2.Put(TokenFiledConst::FIELD_TOKEN_ATTR, static_cast<int32_t>(DEBUG_APP_FLAG));
    value2.Put(TokenFiledConst::FIELD_API_VERSION, 12);
    value2.Put(TokenFiledConst::FIELD_FORBID_PERM_DIALOG, static_cast<int32_t>(1));
    value2.Put(TokenFiledConst::FIELD_UID, static_cast<int32_t>(20100200));
    value2.Put(TokenFiledConst::FIELD_MIGRATED, static_cast<int32_t>(1));
    value2.Put(TokenFiledConst::FIELD_RESERVED, static_cast<int32_t>(ReservedType::RESERVED_DATA));
    values.emplace_back(value2);

    std::vector<HapTokenInfoItem> items;
    HapTokenInfoItem::LoadFromDB(values, items);

    ASSERT_EQ(2u, items.size());

    EXPECT_EQ(static_cast<AccessTokenID>(0x11111111), items[0].tokenId);
    EXPECT_EQ("com.example.one", items[0].bundleName);
    EXPECT_EQ(100u, items[0].userId);
    EXPECT_EQ(APL_NORMAL, items[0].apl);
    EXPECT_EQ(0, items[0].tokenAttr);

    EXPECT_EQ(static_cast<AccessTokenID>(0x22222222), items[1].tokenId);
    EXPECT_EQ("com.example.two", items[1].bundleName);
    EXPECT_EQ(101u, items[1].userId);
    EXPECT_EQ(APL_SYSTEM_CORE, items[1].apl);
    EXPECT_EQ(DEBUG_APP_FLAG, items[1].tokenAttr);
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

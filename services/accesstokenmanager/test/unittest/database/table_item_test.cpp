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

/**
 * @tc.name: BundleInfoItemsBuildAddValue001
 * @tc.desc: Verify BundleInfoItems::BuildAddValue generates correct GenericValues for single module.
 * @tc.type: FUNC
 */
HWTEST_F(TableItemTest, BundleInfoItemsBuildAddValue001, TestSize.Level0)
{
    BundleInfoItems bundleItem;
    bundleItem.bundleName = "com.example.bundle";
    bundleItem.isPreInstalled = true;

    ModuleInfoItem moduleItem;
    moduleItem.moduleName = "entry";
    moduleItem.path = "/data/app/el2/100/base/com.example.bundle";
    moduleItem.bundleType = 0;
    moduleItem.persistData = {0x01, 0x02, 0x03};
    bundleItem.moduleInfoItems.emplace_back(moduleItem);

    std::vector<GenericValues> addValues;
    bundleItem.BuildAddValue(addValues);

    ASSERT_EQ(1u, addValues.size());
    const auto& value = addValues[0];

    EXPECT_EQ("com.example.bundle", value.GetString(TokenFiledConst::FIELD_BUNDLE_NAME));
    EXPECT_NE(0, value.GetInt(TokenFiledConst::FIELD_IS_PREINSTALLED));
    EXPECT_EQ("entry", value.GetString(TokenFiledConst::FIELD_MODULE_NAME));
    EXPECT_EQ("/data/app/el2/100/base/com.example.bundle", value.GetString(TokenFiledConst::FIELD_PATH));
    EXPECT_EQ(0, value.GetInt(TokenFiledConst::FIELD_BUNDLE_TYPE));
}

/**
 * @tc.name: BundleInfoItemsBuildAddValue002
 * @tc.desc: Verify BundleInfoItems::BuildAddValue generates correct GenericValues for multiple modules.
 * @tc.type: FUNC
 */
HWTEST_F(TableItemTest, BundleInfoItemsBuildAddValue002, TestSize.Level0)
{
    BundleInfoItems bundleItem;
    bundleItem.bundleName = "com.example.multi";
    bundleItem.isPreInstalled = false;

    ModuleInfoItem module1;
    module1.moduleName = "entry";
    module1.path = "/path/entry";
    module1.bundleType = 0;
    module1.persistData = {0x01};

    ModuleInfoItem module2;
    module2.moduleName = "feature";
    module2.path = "/path/feature";
    module2.bundleType = 1;
    module2.persistData = {0x02};

    bundleItem.moduleInfoItems.emplace_back(module1);
    bundleItem.moduleInfoItems.emplace_back(module2);

    std::vector<GenericValues> addValues;
    bundleItem.BuildAddValue(addValues);

    ASSERT_EQ(2u, addValues.size());

    EXPECT_EQ("com.example.multi", addValues[0].GetString(TokenFiledConst::FIELD_BUNDLE_NAME));
    EXPECT_EQ("entry", addValues[0].GetString(TokenFiledConst::FIELD_MODULE_NAME));
    EXPECT_EQ("/path/entry", addValues[0].GetString(TokenFiledConst::FIELD_PATH));

    EXPECT_EQ("com.example.multi", addValues[1].GetString(TokenFiledConst::FIELD_BUNDLE_NAME));
    EXPECT_EQ("feature", addValues[1].GetString(TokenFiledConst::FIELD_MODULE_NAME));
    EXPECT_EQ("/path/feature", addValues[1].GetString(TokenFiledConst::FIELD_PATH));
}

/**
 * @tc.name: BundleInfoItemsBuildDeleteValues001
 * @tc.desc: Verify BundleInfoItems::BuildDeleteValues generates correct GenericValues.
 * @tc.type: FUNC
 */
HWTEST_F(TableItemTest, BundleInfoItemsBuildDeleteValues001, TestSize.Level0)
{
    BundleInfoItems bundleItem;
    bundleItem.bundleName = "com.example.delete";

    GenericValues deleteValue;
    bundleItem.BuildDeleteValues(deleteValue);

    EXPECT_EQ("com.example.delete", deleteValue.GetString(TokenFiledConst::FIELD_BUNDLE_NAME));
}

/**
 * @tc.name: BundleInfoItemsBuildUpdateValues001
 * @tc.desc: Verify BundleInfoItems::BuildUpdateValues generates correct delete and add values.
 * @tc.type: FUNC
 */
HWTEST_F(TableItemTest, BundleInfoItemsBuildUpdateValues001, TestSize.Level0)
{
    BundleInfoItems bundleItem;
    bundleItem.bundleName = "com.example.update";
    bundleItem.isPreInstalled = true;

    ModuleInfoItem moduleItem;
    moduleItem.moduleName = "entry";
    moduleItem.path = "/new/path";
    bundleItem.moduleInfoItems.emplace_back(moduleItem);

    GenericValues deleteValue;
    std::vector<GenericValues> addValues;
    bundleItem.BuildUpdateValues(deleteValue, addValues);

    EXPECT_EQ("com.example.update", deleteValue.GetString(TokenFiledConst::FIELD_BUNDLE_NAME));
    ASSERT_EQ(1u, addValues.size());
    EXPECT_EQ("com.example.update", addValues[0].GetString(TokenFiledConst::FIELD_BUNDLE_NAME));
}

/**
 * @tc.name: BundleInfoItemsBuildFindValues001
 * @tc.desc: Verify BundleInfoItems::BuildFindValues generates correct GenericValues.
 * @tc.type: FUNC
 */
HWTEST_F(TableItemTest, BundleInfoItemsBuildFindValues001, TestSize.Level0)
{
    BundleInfoItems bundleItem;
    bundleItem.bundleName = "com.example.find";

    GenericValues findValue;
    bundleItem.BuildFindValues(findValue);

    EXPECT_EQ("com.example.find", findValue.GetString(TokenFiledConst::FIELD_BUNDLE_NAME));
}

/**
 * @tc.name: BundleInfoItemsLoadFromDB001
 * @tc.desc: Verify BundleInfoItems::LoadFromDB correctly loads items with single module.
 * @tc.type: FUNC
 */
HWTEST_F(TableItemTest, BundleInfoItemsLoadFromDB001, TestSize.Level0)
{
    std::vector<GenericValues> values;
    GenericValues value;
    value.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "com.example.load");
    value.Put(TokenFiledConst::FIELD_IS_PREINSTALLED, static_cast<int32_t>(1));
    value.Put(TokenFiledConst::FIELD_MODULE_NAME, "entry");
    value.Put(TokenFiledConst::FIELD_PATH, "/data/app/entry");
    value.Put(TokenFiledConst::FIELD_BUNDLE_TYPE, static_cast<int32_t>(0));
    std::vector<uint8_t> persistData = {0x01, 0x02};
    value.PutBlob(TokenFiledConst::FIELD_PERSIST_DATA, persistData);
    values.emplace_back(value);

    std::vector<BundleInfoItems> items;
    BundleInfoItems::LoadFromDB(values, items);

    ASSERT_EQ(1u, items.size());
    EXPECT_EQ("com.example.load", items[0].bundleName);
    EXPECT_TRUE(items[0].isPreInstalled);
    ASSERT_EQ(1u, items[0].moduleInfoItems.size());
    EXPECT_EQ("entry", items[0].moduleInfoItems[0].moduleName);
    EXPECT_EQ("/data/app/entry", items[0].moduleInfoItems[0].path);
    EXPECT_EQ(0, items[0].moduleInfoItems[0].bundleType);
}

/**
 * @tc.name: BundleInfoItemsLoadFromDB002
 * @tc.desc: Verify BundleInfoItems::LoadFromDB correctly loads items with multiple modules.
 * @tc.type: FUNC
 */
HWTEST_F(TableItemTest, BundleInfoItemsLoadFromDB002, TestSize.Level0)
{
    std::vector<GenericValues> values;

    // Module 1
    GenericValues value1;
    value1.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "com.example.bundle");
    value1.Put(TokenFiledConst::FIELD_IS_PREINSTALLED, static_cast<int32_t>(1));
    value1.Put(TokenFiledConst::FIELD_MODULE_NAME, "entry");
    value1.Put(TokenFiledConst::FIELD_PATH, "/path/entry");
    value1.Put(TokenFiledConst::FIELD_BUNDLE_TYPE, static_cast<int32_t>(0));
    values.emplace_back(value1);

    // Module 2 (same bundle)
    GenericValues value2;
    value2.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "com.example.bundle");
    value2.Put(TokenFiledConst::FIELD_IS_PREINSTALLED, static_cast<int32_t>(1));
    value2.Put(TokenFiledConst::FIELD_MODULE_NAME, "feature");
    value2.Put(TokenFiledConst::FIELD_PATH, "/path/feature");
    value2.Put(TokenFiledConst::FIELD_BUNDLE_TYPE, static_cast<int32_t>(1));
    values.emplace_back(value2);

    std::vector<BundleInfoItems> items;
    BundleInfoItems::LoadFromDB(values, items);

    ASSERT_EQ(1u, items.size());
    EXPECT_EQ("com.example.bundle", items[0].bundleName);
    EXPECT_TRUE(items[0].isPreInstalled);
    ASSERT_EQ(2u, items[0].moduleInfoItems.size());

    EXPECT_EQ("entry", items[0].moduleInfoItems[0].moduleName);
    EXPECT_EQ("/path/entry", items[0].moduleInfoItems[0].path);
    EXPECT_EQ(0, items[0].moduleInfoItems[0].bundleType);

    EXPECT_EQ("feature", items[0].moduleInfoItems[1].moduleName);
    EXPECT_EQ("/path/feature", items[0].moduleInfoItems[1].path);
    EXPECT_EQ(1, items[0].moduleInfoItems[1].bundleType);
}

/**
 * @tc.name: BundleInfoItemsLoadFromDB003
 * @tc.desc: Verify BundleInfoItems::LoadFromDB correctly handles multiple bundles.
 * @tc.type: FUNC
 */
HWTEST_F(TableItemTest, BundleInfoItemsLoadFromDB003, TestSize.Level0)
{
    std::vector<GenericValues> values;

    // Bundle 1
    GenericValues value1;
    value1.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "com.example.bundle1");
    value1.Put(TokenFiledConst::FIELD_IS_PREINSTALLED, static_cast<int32_t>(1));
    value1.Put(TokenFiledConst::FIELD_MODULE_NAME, "entry1");
    value1.Put(TokenFiledConst::FIELD_PATH, "/path1");
    value1.Put(TokenFiledConst::FIELD_BUNDLE_TYPE, static_cast<int32_t>(0));
    values.emplace_back(value1);

    // Bundle 2
    GenericValues value2;
    value2.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "com.example.bundle2");
    value2.Put(TokenFiledConst::FIELD_IS_PREINSTALLED, static_cast<int32_t>(0));
    value2.Put(TokenFiledConst::FIELD_MODULE_NAME, "entry2");
    value2.Put(TokenFiledConst::FIELD_PATH, "/path2");
    value2.Put(TokenFiledConst::FIELD_BUNDLE_TYPE, static_cast<int32_t>(0));
    values.emplace_back(value2);

    std::vector<BundleInfoItems> items;
    BundleInfoItems::LoadFromDB(values, items);

    ASSERT_EQ(2u, items.size());

    EXPECT_EQ("com.example.bundle1", items[0].bundleName);
    EXPECT_TRUE(items[0].isPreInstalled);

    EXPECT_EQ("com.example.bundle2", items[1].bundleName);
    EXPECT_FALSE(items[1].isPreInstalled);
}

/**
 * @tc.name: BundleInfoItemsGenerateAddList001
 * @tc.desc: Verify BundleInfoItems::GenerateAddList generates correct AddInfo.
 * @tc.type: FUNC
 */
HWTEST_F(TableItemTest, BundleInfoItemsGenerateAddList001, TestSize.Level0)
{
    std::vector<GenericValues> values;
    GenericValues value;
    value.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "com.example.gen");
    value.Put(TokenFiledConst::FIELD_MODULE_NAME, "entry");
    values.emplace_back(value);

    std::vector<AddInfo> addInfoVec;
    BundleInfoItems::GenerateAddList(values, addInfoVec);

    ASSERT_EQ(1u, addInfoVec.size());
    EXPECT_EQ(BundleInfoItems::type_, addInfoVec[0].addType);
    ASSERT_EQ(1u, addInfoVec[0].addValues.size());
}

/**
 * @tc.name: BundleInfoItemsGenerateDelList001
 * @tc.desc: Verify BundleInfoItems::GenerateDelList generates correct DelInfo.
 * @tc.type: FUNC
 */
HWTEST_F(TableItemTest, BundleInfoItemsGenerateDelList001, TestSize.Level0)
{
    std::vector<GenericValues> values;
    GenericValues value;
    value.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "com.example.del");
    values.emplace_back(value);

    DelInfo delInfo;
    BundleInfoItems::GenerateDelList(values, delInfo);

    EXPECT_EQ(BundleInfoItems::type_, delInfo.delType);
    EXPECT_EQ("com.example.del", delInfo.delValue.GetString(TokenFiledConst::FIELD_BUNDLE_NAME));
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

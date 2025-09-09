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

#include <dlfcn.h>
#include <gtest/gtest.h>

#define private public
#include "rdb_dlopen_manager.h"
#undef private
#include "token_field_const.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const int32_t WAIT_EVENTHANDLE_TIME = 2;
}
class AccessTokenDatabaseDlopenTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void AccessTokenDatabaseDlopenTest::SetUpTestCase() {}

void AccessTokenDatabaseDlopenTest::TearDownTestCase() {}

void AccessTokenDatabaseDlopenTest::SetUp() {}

void AccessTokenDatabaseDlopenTest::TearDown()
{
    RdbDlopenManager::DestroyInstance();
}

/*
 * @tc.name: GetEventHandler001
 * @tc.desc: RdbDlopenManager::GetEventHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseDlopenTest, GetEventHandler001, TestSize.Level4)
{
    auto instance = RdbDlopenManager::GetInstance();
    ASSERT_NE(nullptr, instance);
    ASSERT_EQ(nullptr, instance->eventRunner_);
    ASSERT_EQ(nullptr, instance->eventHandler_);

    instance->GetEventHandler();
    ASSERT_NE(nullptr, instance->eventRunner_);
    ASSERT_NE(nullptr, instance->eventHandler_);
    instance->GetEventHandler();
}

/*
 * @tc.name: Create001
 * @tc.desc: RdbDlopenManager::Create
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseDlopenTest, Create001, TestSize.Level4)
{
    auto instance = RdbDlopenManager::GetInstance();
    ASSERT_NE(nullptr, instance);
    ASSERT_EQ(nullptr, instance->handle_);
    ASSERT_EQ(nullptr, instance->instance_);

    instance->Init();
    void* handle = nullptr;
    instance->Create(handle);

    handle = dlopen("libaccesstoken_sdk.z.so", RTLD_LAZY);
    ASSERT_NE(nullptr, handle);
    instance->Create(handle);
    ASSERT_EQ(nullptr, instance->instance_);
    dlclose(handle);
    handle = nullptr;

    handle = dlopen(RDB_ADAPTER_LIBPATH, RTLD_LAZY);
    ASSERT_NE(nullptr, handle);
    instance->Create(handle);
    ASSERT_NE(nullptr, instance->instance_);
    dlclose(handle);
    handle = nullptr;
}

/*
 * @tc.name: Destroy001
 * @tc.desc: RdbDlopenManager::Destroy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseDlopenTest, Destroy001, TestSize.Level4)
{
    auto instance = RdbDlopenManager::GetInstance();
    ASSERT_NE(nullptr, instance);
    ASSERT_EQ(nullptr, instance->handle_);
    ASSERT_EQ(nullptr, instance->instance_);

    void* handle = nullptr;
    instance->Destroy(handle);

    handle = dlopen("libaccesstoken_sdk.z.so", RTLD_LAZY);
    ASSERT_NE(nullptr, handle);
    instance->Destroy(handle);
    ASSERT_EQ(nullptr, instance->instance_);
    dlclose(handle);
    handle = nullptr;

    handle = dlopen(RDB_ADAPTER_LIBPATH, RTLD_LAZY);
    ASSERT_NE(nullptr, handle);
    instance->Destroy(handle);
    instance->Create(handle);
    ASSERT_NE(nullptr, instance->instance_);
    instance->Destroy(handle);
    ASSERT_EQ(nullptr, instance->instance_);

    dlclose(handle);
    handle = nullptr;
}

/*
 * @tc.name: DelayDlcloseHandle001
 * @tc.desc: RdbDlopenManager::DelayDlcloseHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseDlopenTest, DelayDlcloseHandle001, TestSize.Level4)
{
    auto instance = RdbDlopenManager::GetInstance();
    ASSERT_NE(nullptr, instance);
    ASSERT_EQ(nullptr, instance->handle_);
    ASSERT_EQ(nullptr, instance->instance_);

    instance->DelayDlcloseHandle(0); // handle_ is nullptr

    instance->handle_ = dlopen("libaccesstoken_sdk.z.so", RTLD_LAZY);
    ASSERT_NE(nullptr, instance->handle_);
    instance->DelayDlcloseHandle(0); // handle_ is not nullptr, instance_ is nullptr
    sleep(WAIT_EVENTHANDLE_TIME);
    ASSERT_EQ(nullptr, instance->handle_);
    
    instance->handle_ = dlopen(RDB_ADAPTER_LIBPATH, RTLD_LAZY);
    ASSERT_NE(nullptr, instance->handle_);
    instance->Create(instance->handle_);
    ASSERT_NE(nullptr, instance->instance_);
    instance->DelayDlcloseHandle(0); // handle_ and instance_ both not nullptr
    sleep(WAIT_EVENTHANDLE_TIME);
    ASSERT_EQ(nullptr, instance->instance_);
    ASSERT_EQ(nullptr, instance->handle_);
}

/*
 * @tc.name: DelayDlcloseHandle002
 * @tc.desc: RdbDlopenManager::DelayDlcloseHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseDlopenTest, DelayDlcloseHandle002, TestSize.Level4)
{
    auto instance = RdbDlopenManager::GetInstance();
    ASSERT_NE(nullptr, instance);
    ASSERT_EQ(nullptr, instance->handle_);
    ASSERT_EQ(nullptr, instance->instance_);
    ASSERT_EQ(0, instance->taskNum_);
    instance->DelayDlcloseHandle(0); // handle_ is nullptr
    instance->handle_ = dlopen(RDB_ADAPTER_LIBPATH, RTLD_LAZY);
    ASSERT_NE(nullptr, instance->handle_);
    instance->Create(instance->handle_);
    ASSERT_NE(nullptr, instance->instance_);
    instance->taskNum_++;
    instance->DelayDlcloseHandle(0); // handle_ and instance_ both not nullptr
    sleep(WAIT_EVENTHANDLE_TIME);
    ASSERT_NE(nullptr, instance->instance_);
    ASSERT_NE(nullptr, instance->handle_);
    instance->taskNum_--;
    instance->DelayDlcloseHandle(0); // handle_ and instance_ both not nullptr
    sleep(WAIT_EVENTHANDLE_TIME);
    ASSERT_EQ(nullptr, instance->instance_);
    ASSERT_EQ(nullptr, instance->handle_);
}

/*
 * @tc.name: DynamicCallTest001
 * @tc.desc: RdbDlopenManager::DynamicCallTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseDlopenTest, DynamicCallTest001, TestSize.Level4)
{
    auto instance = RdbDlopenManager::GetInstance();
    ASSERT_NE(nullptr, instance);

    AtmDataType type = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
    GenericValues addValue;
    addValue.Put(TokenFiledConst::FIELD_NAME, "test");
    addValue.Put(TokenFiledConst::FIELD_VALUE, "test");
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues.emplace_back(addValue);

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    ASSERT_EQ(0, instance->DeleteAndInsertValues(delInfoVec, addInfoVec)); // add a test value to system_config_table

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_NAME, "test");
    std::vector<GenericValues> results1;
    EXPECT_EQ(0, instance->Find(type, conditionValue, results1));
    EXPECT_EQ(1, results1.size());
    EXPECT_EQ("test", results1[0].GetString(TokenFiledConst::FIELD_VALUE));

    GenericValues modifyValue;
    modifyValue.Put(TokenFiledConst::FIELD_NAME, "test");
    modifyValue.Put(TokenFiledConst::FIELD_VALUE, "test123"); // modify "test": "test" to "test": "test123"
    EXPECT_EQ(0, instance->Modify(type, modifyValue, conditionValue));

    std::vector<GenericValues> results2;
    EXPECT_EQ(0, instance->Find(type, conditionValue, results2));
    EXPECT_EQ(1, results2.size());
    EXPECT_EQ("test123", results2[0].GetString(TokenFiledConst::FIELD_VALUE));

    DelInfo delInfo;
    delInfo.delType = type;
    delInfo.delValue = conditionValue;

    std::vector<DelInfo> delInfoVec2;
    delInfoVec2.emplace_back(delInfo);
    std::vector<AddInfo> addInfoVec2;
    // remove test value from system_config_table
    ASSERT_EQ(0, instance->DeleteAndInsertValues(delInfoVec2, addInfoVec2));

    std::vector<GenericValues> results3;
    ASSERT_EQ(0, instance->Find(type, conditionValue, results3));
    ASSERT_EQ(true, results3.empty());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

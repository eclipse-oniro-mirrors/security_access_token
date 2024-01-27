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

#include "accesstoken_database_test.h"
#include "gtest/gtest.h"

#include "access_token_error.h"
#include "data_translator.h"
#include "token_field_const.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
void AccessTokenDatabaseTest::SetUpTestCase()
{
}

void AccessTokenDatabaseTest::TearDownTestCase()
{
}

void AccessTokenDatabaseTest::SetUp()
{
}

void AccessTokenDatabaseTest::TearDown()
{
}

/**
 * @tc.name: DatabaseTranslationTest001
 * @tc.desc: test TranslationIntoGenericValues
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseTest, DatabaseTranslationTest001, TestSize.Level1)
{
    DataTranslator trans;
    PermissionStateFull inPermissionDef;
    inPermissionDef.resDeviceID.resize(0); // 0 is the size

    unsigned int grantIndex = 1; // 1 is a test input
    GenericValues outGenericValues;

    EXPECT_EQ(ERR_PARAM_INVALID, trans.TranslationIntoGenericValues(inPermissionDef, grantIndex, outGenericValues));
}

/**
 * @tc.name: DatabaseTranslationTest002
 * @tc.desc: test TranslationIntoPermissionStateFull
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseTest, DatabaseConverage002, TestSize.Level1)
{
    DataTranslator trans;
    GenericValues inGenericValues;
    PermissionStateFull outPermissionState;
    outPermissionState.permissionName = ""; // empty name

    EXPECT_EQ(ERR_PARAM_INVALID, trans.TranslationIntoPermissionStateFull(inGenericValues, outPermissionState));

    outPermissionState.permissionName = "test name"; // test name
    inGenericValues.Put(TokenFiledConst::FIELD_DEVICE_ID, ""); // empty device id
    EXPECT_EQ(ERR_PARAM_INVALID, trans.TranslationIntoPermissionStateFull(inGenericValues, outPermissionState));

    inGenericValues.Put(TokenFiledConst::FIELD_DEVICE_ID, "test dev id");
    inGenericValues.Put(TokenFiledConst::FIELD_GRANT_FLAG, 0xffff); // 0xffff is test input
    EXPECT_EQ(ERR_PARAM_INVALID, trans.TranslationIntoPermissionStateFull(inGenericValues, outPermissionState));
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

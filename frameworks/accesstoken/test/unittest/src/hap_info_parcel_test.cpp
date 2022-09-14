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
#include "accesstoken_log.h"
#include "access_token.h"
#include "hap_info_parcel.h"
#include "parcel.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t DEFAULT_API_VERSION = 8;
}
class HapInfoParcelTest : public testing::Test  {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HapInfoParcelTest::SetUpTestCase(void) {}
void HapInfoParcelTest::TearDownTestCase(void) {}
void HapInfoParcelTest::SetUp(void) {}
void HapInfoParcelTest::TearDown(void) {}

/**
 * @tc.name: HapInfoParcel001
 * @tc.desc: Verify the CreateHapTokenInfo add one hap token function.
 * @tc.type: FUNC
 * @tc.require: I5QKZF
 */
HWTEST_F(HapInfoParcelTest, HapInfoParcel001, TestSize.Level1)
{
    HapInfoParcel hapinfoParcel;
    hapinfoParcel.hapInfoParameter = {
        .userID = 1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION,
    };

    Parcel parcel;
    EXPECT_EQ(true, hapinfoParcel.Marshalling(parcel));

    std::shared_ptr<HapInfoParcel> readedData(HapInfoParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);

    EXPECT_EQ(hapinfoParcel.hapInfoParameter.userID, readedData->hapInfoParameter.userID);
    EXPECT_EQ(true, hapinfoParcel.hapInfoParameter.bundleName == readedData->hapInfoParameter.bundleName);
    EXPECT_EQ(hapinfoParcel.hapInfoParameter.instIndex, readedData->hapInfoParameter.instIndex);
    EXPECT_EQ(true, hapinfoParcel.hapInfoParameter.appIDDesc == readedData->hapInfoParameter.appIDDesc);
    EXPECT_EQ(hapinfoParcel.hapInfoParameter.apiVersion, readedData->hapInfoParameter.apiVersion);
}
}
}
}
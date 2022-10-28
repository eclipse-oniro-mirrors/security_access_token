/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <thread>

#include "privacy_kit_test.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "parameter.h"
#include "privacy_error.h"
#include "privacy_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Security {
namespace AccessToken {

void PrivacyKitTest::SetUpTestCase()
{
}

void PrivacyKitTest::TearDownTestCase()
{
}

void PrivacyKitTest::SetUp()
{
}

void PrivacyKitTest::TearDown()
{
}

/**
 * @tc.name: IsAllowedUsingPermissionTest001
 * @tc.desc: Verify the IsAllowedUsingPermission abnormal branch return nullptr proxy.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX3 issueI5RWX8
 */
HWTEST_F(PrivacyKitTest, IsAllowedUsingPermissionTest001, TestSize.Level1)
{
    AccessTokenID g_TokenId_A = 0xff;
    std::string permissionName = "ohos.permission.CAMERA";
    bool ret = PrivacyKit::IsAllowedUsingPermission(g_TokenId_A, permissionName);
    ASSERT_EQ(false, ret);
}

class CbCustomizeTest4 : public StateCustomizedCbk {
public:
    CbCustomizeTest4()
    {}

    ~CbCustomizeTest4()
    {}

    virtual void StateChangeNotify(AccessTokenID tokenId, bool isShow)
    {}
};

/**
 * @tc.name: StartUsingPermissionTest001
 * @tc.desc: Verify the StartUsingPermission abnormal branch return nullptr proxy.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PrivacyKitTest, StartUsingPermissionTest001, TestSize.Level1)
{
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    AccessTokenID g_TokenId_A = 0xff;
    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(PrivacyError::ERR_SERVICE_ABNORMAL,
        PrivacyKit::StartUsingPermission(g_TokenId_A, permissionName, callbackPtr));
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

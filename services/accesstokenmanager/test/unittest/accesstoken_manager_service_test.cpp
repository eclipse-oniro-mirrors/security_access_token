/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "accesstoken_manager_service_test.h"
#include "gtest/gtest.h"

#include "parameters.h"
#include "accesstoken_manager_service.h"
#include "access_token_error.h"
#include "atm_tools_param_info_parcel.h"
const char* DEVELOPER_MODE_STATE = "const.security.developermode.state";


using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
void AccessTokenManagerServiceTest::SetUpTestCase()
{
}

void AccessTokenManagerServiceTest::TearDownTestCase()
{
}

void AccessTokenManagerServiceTest::SetUp()
{
}

void AccessTokenManagerServiceTest::TearDown()
{
}

/**
 * @tc.name: DumpTokenInfoFuncTest001
 * @tc.desc: test DumpTokenInfo with DEVELOPER_MODE_STATE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenManagerServiceTest, DumpTokenInfoFuncTest001, TestSize.Level1)
{
    std::string dumpInfo;
    AtmToolsParamInfoParcel infoParcel;
    infoParcel.info.processName = "hdcd";

    system::SetBoolParameter(DEVELOPER_MODE_STATE, false);
    bool ret = system::GetBoolParameter(DEVELOPER_MODE_STATE, false);
    ASSERT_FALSE(ret);

    std::shared_ptr<AccessTokenManagerService> atManagerService_ =
        DelayedSingleton<AccessTokenManagerService>::GetInstance();
    atManagerService_->DumpTokenInfo(infoParcel, dumpInfo);
    ASSERT_EQ("Developer mode not support.", dumpInfo);

    system::SetBoolParameter(DEVELOPER_MODE_STATE, true);
    ret = system::GetBoolParameter(DEVELOPER_MODE_STATE, false);
    ASSERT_TRUE(ret);
    atManagerService_->DumpTokenInfo(infoParcel, dumpInfo);
    ASSERT_NE("", dumpInfo);
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

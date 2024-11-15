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
#include "test_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
void TestCommon::GetHapParams(HapInfoParams& infoParams, HapPolicyParams& policyParams)
{
    infoParams.userID = 0;
    infoParams.bundleName = "com.ohos.AccessTokenTestBundle";
    infoParams.instIndex = 0;
    infoParams.appIDDesc = "AccessTokenTestAppID";
    infoParams.apiVersion = TestCommon::DEFAULT_API_VERSION;
    infoParams.isSystemApp = true;
    infoParams.appDistributionType = "";

    policyParams.apl = APL_NORMAL;
    policyParams.domain = "accesstoken_test_domain";
    policyParams.permList = {};
    policyParams.permStateList = {};
    policyParams.aclRequestedList = {};
    policyParams.preAuthorizationInfo = {};
}
}  // namespace SecurityComponent
}  // namespace Security
}  // namespace OHOS
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
#ifndef TEST_TOOL_COMMON_H
#define TEST_TOOL_COMMON_H

#include <string>
#include <vector>
#include "access_token.h"
#include "hap_token_info.h"

void PrintCurrentTime();
OHOS::Security::AccessToken::AccessTokenID GetNativeTokenId(const std::string& process);
void BuildHapPolicyParams(const std::vector<std::string>& reqPerm,
    const std::vector<std::string>& preAuthPerm, OHOS::Security::AccessToken::HapPolicyParams& policyParams);
OHOS::Security::AccessToken::FullTokenID GetHapTokenId(
    const std::string& bundle, const std::vector<std::string>& reqPerm,
    const std::vector<std::string>& preAuthPerm = {}, bool isSystemApp = true, int32_t userId = 0);
int32_t DeleteHapTokenID(const std::string& bundleName, bool isReservedTokenId);

#endif  // TEST_TOOL_COMMON_H

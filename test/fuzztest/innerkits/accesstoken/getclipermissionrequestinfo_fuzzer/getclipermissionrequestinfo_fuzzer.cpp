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

#include "getclipermissionrequestinfo_fuzzer.h"

#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "claw_permission_fuzzdata.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mock_permission.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
bool GetCliPermissionRequestInfoFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MockToken mock({ "ohos.permission.QUERY_TOOL_PERMISSIONS" }, true, true);
    FuzzedDataProvider provider(data, size);
    std::string agentID = ConsumeAgentID(provider);
    std::vector<CliInfo> cliInfoList = ConsumeCliInfoList(provider);
    if (provider.ConsumeBool() || cliInfoList.empty()) {
        AppendKnownCliInfos(provider, cliInfoList);
    }
    PermissionDialogResult result;
    return AccessTokenKit::GetCliPermissionRequestInfo(agentID, cliInfoList, result) == RET_SUCCESS;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::GetCliPermissionRequestInfoFuzzTest(data, size);
    return 0;
}

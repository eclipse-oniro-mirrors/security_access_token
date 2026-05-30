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

#include "getskillpermissionrequestinfostub_fuzzer.h"

#include <new>
#include <vector>

#include "accesstoken_kit.h"
#include "claw_permission_fuzzdata.h"
#include "fuzzer/FuzzedDataProvider.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "iaccess_token_manager.h"
#include "message_parcel.h"
#include "mock_permission.h"
#include "skill_info_parcel.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
const std::string DEFAULT_AGENT_ID = "1001";
const std::string DEFAULT_BUNDLE_NAME = "com.ohos.fuzz";
const std::string DEFAULT_MODULE_NAME = "entry";
const std::string DEFAULT_SKILL_NAME = "fuzzSkill";
const std::string QUERY_TOOL_PERMISSIONS = "ohos.permission.QUERY_TOOL_PERMISSIONS";

void InitializeClawPermissionStubFuzz()
{
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
}

bool WriteSkillInfoParcelsToParcel(MessageParcel& data, FuzzedDataProvider& provider)
{
    std::vector<SkillInfo> infos = ConsumeSkillInfoList(provider);
    if (provider.ConsumeBool() && infos.empty()) {
        infos.push_back({ DEFAULT_SKILL_NAME, DEFAULT_BUNDLE_NAME, DEFAULT_MODULE_NAME });
    }
    if (!data.WriteInt32(static_cast<int32_t>(infos.size()))) {
        return false;
    }
    for (const auto& info : infos) {
        SkillInfoParcel parcel;
        parcel.skillInfo = info;
        if (!data.WriteParcelable(&parcel)) {
            return false;
        }
    }
    return true;
}
}

bool GetSkillPermissionRequestInfoStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MockToken caller({ QUERY_TOOL_PERMISSIONS }, true, true);
    FuzzedDataProvider provider(data, size);
    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    std::string agentId = provider.ConsumeBool() ? DEFAULT_AGENT_ID : ConsumeAgentID(provider);
    if (!datas.WriteString(agentId)) {
        return false;
    }
    if (!WriteSkillInfoParcelsToParcel(datas, provider)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_SKILL_PERMISSION_REQUEST_INFO),
        datas, reply, option);
    return true;
}
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    OHOS::InitializeClawPermissionStubFuzz();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::GetSkillPermissionRequestInfoStubFuzzTest(data, size);
    return 0;
}

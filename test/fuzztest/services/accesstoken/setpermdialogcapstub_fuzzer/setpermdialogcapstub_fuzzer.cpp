/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#include "setpermdialogcapstub_fuzzer.h"

#include <climits>
#include <string>
#include <thread>
#include <vector>

#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_service_context_helper.h"
#include "iaccess_token_manager.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
const std::string DEFAULT_CALLER_BUNDLE = "setpermdialogcapstub.fuzzer";
const std::string DISABLE_PERMISSION_DIALOG = "ohos.permission.DISABLE_PERMISSION_DIALOG";
uint64_t g_callerFullTokenId = 0;
}

void Initialize()
{
    FuzzServiceContext::InitializeServiceCallerContext(
        g_callerFullTokenId, DEFAULT_CALLER_BUNDLE, DISABLE_PERMISSION_DIALOG);
}

bool SetPermDialogCapStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzServiceContext::CallingContextGuard guard(g_callerFullTokenId);
    FuzzedDataProvider provider(data, size);
    HapBaseInfoParcel baseInfoParcel;
    baseInfoParcel.hapBaseInfo.userID = provider.ConsumeIntegralInRange<int32_t>(-1, INT_MAX);
    baseInfoParcel.hapBaseInfo.bundleName = provider.ConsumeRandomLengthString();
    baseInfoParcel.hapBaseInfo.instIndex = provider.ConsumeIntegral<int32_t>();

    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!datas.WriteParcelable(&baseInfoParcel)) {
        return false;
    }
    uint32_t code = static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_SET_PERM_DIALOG_CAP);

    MessageParcel reply;
    MessageOption option;

    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    return true;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Initialize();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetPermDialogCapStubFuzzTest(data, size);
    return 0;
}

} // namespace OHOS

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

#ifndef EL5_FILEKEY_MANAGER_STUB_H
#define EL5_FILEKEY_MANAGER_STUB_H

#include <map>

#include "el5_filekey_manager_interface.h"
#include "el5_filekey_manager_log.h"
#include "iremote_stub.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class El5FilekeyManagerStub : public IRemoteStub<El5FilekeyManagerInterface> {
public:
    El5FilekeyManagerStub();
    virtual ~El5FilekeyManagerStub();
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    void SetFuncInMap();
    void AcquireAccessInner(MessageParcel &data, MessageParcel &reply);
    void ReleaseAccessInner(MessageParcel &data, MessageParcel &reply);
    void GenerateAppKeyInner(MessageParcel &data, MessageParcel &reply);
    void DeleteAppKeyInner(MessageParcel &data, MessageParcel &reply);
    void GetUserAppKeyInner(MessageParcel &data, MessageParcel &reply);
    void ChangeUserAppkeysLoadInfoInner(MessageParcel &data, MessageParcel &reply);
    void SetFilePathPolicyInner(MessageParcel &data, MessageParcel &reply);
    void RegisterCallbackInner(MessageParcel &data, MessageParcel &reply);

    void MarshallingKeyInfos(MessageParcel &reply, std::vector<std::pair<int32_t, std::string>>& keyInfos);
    int32_t UnmarshallingLoadInfos(MessageParcel &data, std::vector<std::pair<std::string, bool>> &loadInfos);

    using RequestType = void (El5FilekeyManagerStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, RequestType> requestMap_;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif // EL5_FILEKEY_MANAGER_STUB_H

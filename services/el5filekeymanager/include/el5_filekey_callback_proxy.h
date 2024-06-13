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

#ifndef EL5_FILEKEY_CALLBACK_PROXY_H
#define EL5_FILEKEY_CALLBACK_PROXY_H

#include "el5_filekey_callback_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class El5FilekeyCallbackProxy : public IRemoteProxy<El5FilekeyCallbackInterface> {
public:
    explicit El5FilekeyCallbackProxy(const sptr<IRemoteObject>& impl);
    virtual ~El5FilekeyCallbackProxy();

    void OnRegenerateAppKey(std::vector<AppKeyInfo> &infos) override;
private:
    static inline BrokerDelegator<El5FilekeyCallbackProxy> delegator_;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif // EL5_FILEKEY_CALLBACK_PROXY_H

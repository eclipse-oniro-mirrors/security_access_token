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

#ifndef ACCESSTOKEN_CAMERA_MANAGER_ADAPTER_H
#define ACCESSTOKEN_CAMERA_MANAGER_ADAPTER_H

#include <mutex>
#include <string>

#include <iremote_proxy.h>
#include "nocopyable.h"
#include "privacy_param.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class CameraManagerAdapter final {
private:
    CameraManagerAdapter();
    virtual ~CameraManagerAdapter();
    DISALLOW_COPY_AND_MOVE(CameraManagerAdapter);

public:
    static CameraManagerAdapter& GetInstance();

    int32_t MuteCameraPersist(PolicyType policyType, bool muteMode);
    bool IsCameraMuted();

private:
    void InitProxy();

    class CameraManagerDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        CameraManagerDeathRecipient() = default;
        ~CameraManagerDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;
    private:
        DISALLOW_COPY_AND_MOVE(CameraManagerDeathRecipient);
    };

    sptr<IRemoteObject> GetProxy();
    void ReleaseProxy(const wptr<IRemoteObject>& remote);

    std::mutex proxyMutex_;
    sptr<IRemoteObject> proxy_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_CAMERA_MANAGER_ADAPTER_H

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
#include "power_manager_access_loader.h"

#include "power_mgr_client.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool PowerManagerLoader::IsScreenOn()
{
    bool isScreenOn = PowerMgr::PowerMgrClient::GetInstance().IsScreenOn();
    delete &PowerMgr::PowerMgrClient::GetInstance();
    return isScreenOn;
}

void PowerManagerLoader::WakeupDevice()
{
    PowerMgr::PowerMgrClient::GetInstance().WakeupDevice();
}

extern "C" {
void* Create()
{
    return reinterpret_cast<void*>(new PowerManagerLoader);
}

void Destroy(void* loaderPtr)
{
    PowerManagerLoaderInterface* loader = reinterpret_cast<PowerManagerLoaderInterface*>(loaderPtr);
    if (loader != nullptr) {
        delete loader;
    }
}
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

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

#ifndef ABILITY_MANAGER_ACCESS_LOADER_H
#define ABILITY_MANAGER_ACCESS_LOADER_H

#include <iremote_proxy.h>

#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
    const int32_t DEFAULT_VALUE = -1;
}
const static std::string ABILITY_MANAGER_LIBPATH = "libaccesstoken_ability_manager_adapter.z.so";

class AbilityManagerAccessLoaderInterface {
public:
    AbilityManagerAccessLoaderInterface() {}
    virtual ~AbilityManagerAccessLoaderInterface() {}
    virtual int32_t StartAbility(const AAFwk::Want &want, const sptr<IRemoteObject> &callerToken,
        int32_t requestCode = DEFAULT_VALUE, int32_t userId = DEFAULT_VALUE);
};

class AbilityManagerAccessLoader final: public AbilityManagerAccessLoaderInterface {
    int32_t StartAbility(const AAFwk::Want &want, const sptr<IRemoteObject> &callerToken,
        int32_t requestCode = DEFAULT_VALUE, int32_t userId = DEFAULT_VALUE) override;
};

#ifdef __cplusplus
extern "C" {
#endif
    void* Create();
    void Destroy(void* loaderPtr);
#ifdef __cplusplus
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ABILITY_MANAGER_ACCESS_LOADER_H
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

#ifndef INTERFACES_ETS_ANI_PRIVACY_MANAGER_H
#define INTERFACES_ETS_ANI_PRIVACY_MANAGER_H

#include <memory>
#include <thread>
#include <string>
#include <vector>

#include "ani.h"
#include "perm_active_status_customized_cbk.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermActiveStatusPtr : public std::enable_shared_from_this<PermActiveStatusPtr>,
    public PermActiveStatusCustomizedCbk {
public:
    explicit PermActiveStatusPtr(const std::vector<std::string>& permList);
    ~PermActiveStatusPtr() override;
    void ActiveStatusChangeCallback(ActiveChangeResponse& result) override;
    void SetVm(ani_vm* vm);
    void SetEnv(ani_env* env);
    void SetCallbackRef(const ani_ref& ref);
    void SetThreadId(const std::thread::id threadId);
private:
    ani_env* env_ = nullptr;
    ani_vm* vm_ = nullptr;
    ani_ref ref_ = nullptr;
    std::thread::id threadId_;
};

struct RegisterPermActiveChangeContext {
    ani_env* env = nullptr;
    ani_ref callbackRef = nullptr;
    std::string type;
    std::vector<std::string> permissionList;
    std::shared_ptr<PermActiveStatusPtr> subscriber = nullptr;
    std::thread::id threadId;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif /* INTERFACES_ETS_ANI_PRIVACY_MANAGER_H */

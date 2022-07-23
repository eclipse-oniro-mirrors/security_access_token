/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef PERM_ACTIVE_STATUS_CHANGE_CALLBACK_H
#define PERM_ACTIVE_STATUS_CHANGE_CALLBACK_H

#include <string>
#include <vector>

#include "active_change_response_info.h"
#include "perm_active_status_change_callback_stub.h"
#include "perm_active_status_customized_cbk.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermActiveStatusChangeCallback : public PermActiveStatusChangeCallbackStub {
public:
    explicit PermActiveStatusChangeCallback(const std::shared_ptr<PermActiveStatusCustomizedCbk> &subscriber);
    ~PermActiveStatusChangeCallback() override;

    void ActiveStatusChangeCallback(ActiveChangeResponse& result) override;

    void Stop();

private:
    std::shared_ptr<PermActiveStatusCustomizedCbk> customizedCallback_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif  // PERM_ACTIVE_STATUS_CHANGE_CALLBACK_H
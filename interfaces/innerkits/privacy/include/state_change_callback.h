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

#ifndef STATE_CHANGE_CALLBACK_H
#define STATE_CHANGE_CALLBACK_H

#include "state_change_callback_stub.h"
#include "state_customized_cbk.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class StateChangeCallback : public StateChangeCallbackStub {
public:
    StateChangeCallback(const std::shared_ptr<StateCustomizedCbk> &customizedCallback);
    ~StateChangeCallback() override;

    void StateChangeNotify(AccessTokenID tokenId, bool isShowing) override;

    void Stop();

private:
    std::shared_ptr<StateCustomizedCbk> customizedCallback_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif  // STATE_CHANGE_CALLBACK_H

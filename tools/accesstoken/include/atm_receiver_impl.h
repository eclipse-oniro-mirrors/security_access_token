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

#ifndef ACCESSTOKENMANAGER_RECEIVER_IMPL_H
#define ACCESSTOKENMANAGER_RECEIVER_IMPL_H

#include <future>
#include "status_receiver_host.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AtmReceiverImpl : public AppExecFwk::StatusReceiverHost {
public:
    AtmReceiverImpl();
    virtual ~AtmReceiverImpl() override;

    virtual void OnStatusNotify(const int process) override;
    virtual void OnFinished(const int32_t resultCode, const std::string &resultMsg) override;
    int32_t GetResultCode() const;

private:
    mutable std::promise<int32_t> resultMsgSignal_;

    DISALLOW_COPY_AND_MOVE(AtmReceiverImpl);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESSTOKENMANAGER_RECEIVER_IMPL_H

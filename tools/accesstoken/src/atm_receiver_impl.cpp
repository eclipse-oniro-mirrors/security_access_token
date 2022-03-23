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

#include "accesstoken_log.h"
#include "atm_receiver_impl.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenManagerTools"
};
}

AtmReceiverImpl::AtmReceiverImpl()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "create atm status receiver instance");
}

AtmReceiverImpl::~AtmReceiverImpl()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "destory atm status receiver instance");
}

void AtmReceiverImpl::OnFinished(const int32_t resultCode, const std::string &resultMsg)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "on finished result is %{public}d, %{public}s", resultCode, resultMsg.c_str());
    resultMsgSignal_.set_value(resultCode);
}

void AtmReceiverImpl::OnStatusNotify(const int process)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "on OnStatusNotify is %{public}d", process);
}

int32_t AtmReceiverImpl::GetResultCode() const
{
    auto future = resultMsgSignal_.get_future();
    future.wait();
    int32_t resultCode = future.get();

    return resultCode;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

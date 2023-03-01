/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

/**
 * @addtogroup TokenCallback
 * @{
 *
 * @brief Provides napi RequestPermissionsFromUser callback interface
 *
 * @since 8.0
 * @version 8.0
 */

/**
 * @file token_callback_stub.h
 *
 * @brief Declares TokenCallbackStub class.
 *
 * @since 8.0
 * @version 8.0
 */

#ifndef I_TOKEN_CALLBACK_STUB_H
#define I_TOKEN_CALLBACK_STUB_H

#include "i_token_callback.h"

#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Declares TokenCallbackStub class
 */
class TokenCallbackStub : public IRemoteStub<ITokenCallback> {
public:
    /**
     * @brief Default constructor without any param.
     */
    TokenCallbackStub() = default;
    /**
     * @brief Default destructor without any param.
     */
    virtual ~TokenCallbackStub() = default;

    /**
     * @brief Ipc trans fuction.
     * @param code interface code, see i_token_callback.h InterfaceCode
     * @param data ipc requst data
     * @param reply ipc response data
     * @param option some ipc comm parameter
     * @return ipc comm exec result
     */
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // I_TOKEN_CALLBACK_STUB_H
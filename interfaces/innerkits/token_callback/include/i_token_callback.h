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
 * @file i_token_callback.h
 *
 * @brief Declares ITokenCallback interface interfaces.
 *
 * @since 8.0
 * @version 8.0
 */

#ifndef I_TOKEN_CALLBACK_H
#define I_TOKEN_CALLBACK_H

#include <iremote_broker.h>
#include "accesstoken_grant_result_ipc_interface_code.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Declares ITokenCallback interface class
 */
class ITokenCallback : public IRemoteBroker {
public:
    /**
     * @brief declare interface descritor which used in parcel.
     * @param const string
     */
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.accesstoken.tokencallback");

    /**
     * @brief pure virtual fuction.
     * @param permissions permission name list
     * @param grantResults permission grant result
     */
    virtual void GrantResultsCallback(
        const std::vector<std::string> &permissions, const std::vector<int> &grantResults) = 0;

    /**
     * @brief pure virtual fuction.
     */
    virtual void WindowShownCallback() {};

    /** interface enum */
    enum InterfaceCode {
        GRANT_RESULT_CALLBACK = 0,
        WINDOW_DESTORY_CALLBACK,
    };
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif  // I_TOKEN_CALLBACK_H
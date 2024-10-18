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
 * @addtogroup Privacy
 * @{
 *
 * @brief Provides sensitive data access management.
 *
 * @since 8.0
 * @version 8.0
 */

/**
 * @file on_permission_used_record_callback.h
 *
 * @brief Declares OnPermissionUsedRecordCallback class.
 *
 * @since 8.0
 * @version 8.0
 */

#ifndef ON_PERMISSION_USED_RECORD_CALLBACK_H
#define ON_PERMISSION_USED_RECORD_CALLBACK_H

#include "errors.h"
#include "iremote_broker.h"
#include "permission_used_result.h"
#include "privacy_permission_record_ipc_interface_code.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Declares OnPermissionUsedRecordCallback interface class
 */
class OnPermissionUsedRecordCallback : public IRemoteBroker {
public:
    /**
     * @brief declare interface descritor which used in parcel.
     * @param const string
     */
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.accesstoken.OnPermissionUsedRecordCallback");

    /**
     * @brief pure virtual fuction.
     * @param code error code
     * @param result PermissionUsedResult quote, as callback info
     */
    virtual void OnQueried(ErrCode code, PermissionUsedResult& result) = 0;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ON_PERMISSION_USED_RECORD_CALLBACK_H

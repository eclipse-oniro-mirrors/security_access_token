/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
 * @brief Provides sensitive permissions access management.
 *
 * @since 8.0
 * @version 8.0
 */

/**
 * @file sec_comp_enhance_data.h
 *
 * @brief Declares security component enhance deposit data struct.
 *
 * @since 10.0
 * @version 10.0
 */

#ifndef INTERFACE_INNER_KITS_PRIVACY_SEC_COMP_ENHANCE_DATA_H
#define INTERFACE_INNER_KITS_PRIVACY_SEC_COMP_ENHANCE_DATA_H

#include "access_token.h"
#include "iremote_object.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Declares security component enhance data struct only for security component service
 */
struct SecCompEnhanceData {
    /**
     * callback remote object for checking security component valid.
     */
    sptr<IRemoteObject> callback;
    /**
     * pid for which used security component.
     */
    int32_t pid;
    /**
     * token id for which used security component.
     */
    AccessTokenID token;
    /**
     * challenge for register.
     */
    uint64_t challenge;
    /**
     * sessionId for register.
     */
    int32_t sessionId;
    /**
     * sequence number of session.
     */
    int32_t seqNum;
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // INTERFACE_INNER_KITS_PRIVACY_SEC_COMP_ENHANCE_DATA_H


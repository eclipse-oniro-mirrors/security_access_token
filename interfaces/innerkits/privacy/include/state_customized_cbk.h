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
 * @file state_customized_cbk.h
 *
 * @brief Declares StateCustomizedCbk class.
 *
 * @since 8.0
 * @version 8.0
 */

#ifndef STATE_CUSTOMIZED_CBK_H
#define STATE_CUSTOMIZED_CBK_H

#include <cstdint>
#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Declares StateCustomizedCbk class.
 */
class StateCustomizedCbk {
public:
    /**
     * @brief Constructor without any param.
     */
    StateCustomizedCbk();
    /**
     * @brief Destructor without any param.
     */
    virtual ~StateCustomizedCbk();

    /**
     * @brief Pure virtual function for callback.
     * @param tokenId token id
     * @param isShowing whether camera float window is show or not
     */
    virtual void StateChangeNotify(AccessTokenID tokenId, bool isShowing) = 0;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // STATE_CUSTOMIZED_CBK_H

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

#ifndef CONSTANT_H
#define CONSTANT_H

#include <algorithm>
#include <string>

namespace OHOS {
namespace Security {
namespace AccessToken {
class Constant {
public:
    /**
     * Indicates message format version, should be compatible.
     */
    const static int32_t DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION = 2;

    /**
     * Status code, indicates general success.
     */
    const static int32_t SUCCESS = 0;

    /**
     * Status code, indicates general failure.
     */
    const static int32_t FAILURE = -1;

    /**
     * Status code, indicates failure but can retry.
     */
    const static int32_t FAILURE_BUT_CAN_RETRY = -2;

    /**
     * Status Code, indicates invalid command.
     */
    const static int32_t INVALID_COMMAND = -14;

    /**
     * Session Id, indicates invalid session.
     */
    const static int32_t INVALID_SESSION = -1;

    /**
     * Command status code, indicate a status of command before RPC call.
     */
    const static int32_t STATUS_CODE_BEFORE_RPC = 100001;

    /**
     * Command result string, indicates success.
     */
    static const std::string COMMAND_RESULT_SUCCESS;

    /**
     * Command result string, indicates failed.
     */
    static const std::string COMMAND_RESULT_FAILED;
    const static int32_t DELAY_SYNC_TOKEN_MS = 3000;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // CONSTANT_H

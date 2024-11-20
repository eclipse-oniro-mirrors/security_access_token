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

#ifndef PRIVACY_FIELD_CONST_H
#define PRIVACY_FIELD_CONST_H

#include <string>

namespace OHOS {
namespace Security {
namespace AccessToken {
class PrivacyFiledConst {
public:
    inline static constexpr const char* FIELD_TOKEN_ID = "token_id";
    inline static constexpr const char* FIELD_DEVICE_ID = "device_id";
    inline static constexpr const char* FIELD_OP_CODE = "op_code";
    inline static constexpr const char* FIELD_STATUS = "status";
    inline static constexpr const char* FIELD_TIMESTAMP = "timestamp";
    inline static constexpr const char* FIELD_ACCESS_DURATION = "access_duration";
    inline static constexpr const char* FIELD_ACCESS_COUNT = "access_count";
    inline static constexpr const char* FIELD_REJECT_COUNT = "reject_count";

    inline static constexpr const char* FIELD_TIMESTAMP_BEGIN = "timestamp_begin";
    inline static constexpr const char* FIELD_TIMESTAMP_END = "timestamp_end";
    inline static constexpr const char* FIELD_FLAG = "flag";
    inline static constexpr const char* FIELD_LOCKSCREEN_STATUS = "lockScreenStatus";

    inline static constexpr const char* FIELD_PERMISSION_CODE = "permission_code";
    inline static constexpr const char* FIELD_USED_TYPE = "used_type";
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PRIVACY_FIELD_CONST_H

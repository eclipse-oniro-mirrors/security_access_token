/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_NAPI_HISYSEVENT_ADAPTER_H
#define ACCESSTOKEN_NAPI_HISYSEVENT_ADAPTER_H

namespace OHOS {
namespace Security {
namespace AccessToken {
enum ReqPermFromUserErrorCode {
    TOKENID_INCONSISTENCY = 0,
    ABILITY_FLAG_ERROR = 1,
    GET_UI_CONTENT_FAILED = 2,
    CREATE_MODAL_UI_FAILED = 3,
    TRIGGER_RELEASE = 4,
    TRIGGER_ONERROR = 5,
    TRIGGER_DESTROY = 6,
};
enum VerifyAccessTokenEventCode {
    VERIFY_TOKENID_INCONSISTENCY = 0,
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_NAPI_HISYSEVENT_ADAPTER_H
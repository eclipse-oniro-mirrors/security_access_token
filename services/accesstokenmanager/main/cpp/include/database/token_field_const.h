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

#ifndef TOKEN_FIELD_CONST_H
#define TOKEN_FIELD_CONST_H

#include <string>

namespace OHOS {
namespace Security {
namespace AccessToken {
class TokenFiledConst {
public:
    inline static constexpr const char* FIELD_TOKEN_ID = "token_id";
    inline static constexpr const char* FIELD_USER_ID = "user_id";
    inline static constexpr const char* FIELD_BUNDLE_NAME = "bundle_name";
    inline static constexpr const char* FIELD_INST_INDEX = "inst_index";
    inline static constexpr const char* FIELD_DLP_TYPE = "dlp_type";
    inline static constexpr const char* FIELD_APP_ID = "app_id";
    inline static constexpr const char* FIELD_DEVICE_ID = "device_id";
    inline static constexpr const char* FIELD_APL = "apl";
    inline static constexpr const char* FIELD_TOKEN_VERSION = "token_version";
    inline static constexpr const char* FIELD_TOKEN_ATTR = "token_attr";
    inline static constexpr const char* FIELD_API_VERSION = "api_version";
    inline static constexpr const char* FIELD_FORBID_PERM_DIALOG = "perm_dialog_cap_state";
    inline static constexpr const char* FIELD_PROCESS_NAME = "process_name";
    inline static constexpr const char* FIELD_DCAP = "dcap";
    inline static constexpr const char* FIELD_NATIVE_ACLS = "native_acls";
    inline static constexpr const char* FIELD_PERMISSION_NAME = "permission_name";
    inline static constexpr const char* FIELD_GRANT_MODE = "grant_mode";
    inline static constexpr const char* FIELD_AVAILABLE_LEVEL = "available_level";
    inline static constexpr const char* FIELD_PROVISION_ENABLE = "provision_enable";
    inline static constexpr const char* FIELD_DISTRIBUTED_SCENE_ENABLE = "distributed_scene_enable";
    inline static constexpr const char* FIELD_LABEL = "label";
    inline static constexpr const char* FIELD_LABEL_ID = "label_id";
    inline static constexpr const char* FIELD_DESCRIPTION = "description";
    inline static constexpr const char* FIELD_DESCRIPTION_ID = "description_id";
    inline static constexpr const char* FIELD_AVAILABLE_TYPE = "available_type";
    inline static constexpr const char* FIELD_GRANT_IS_GENERAL = "is_general";
    inline static constexpr const char* FIELD_GRANT_STATE = "grant_state";
    inline static constexpr const char* FIELD_GRANT_FLAG = "grant_flag";
    inline static constexpr const char* FIELD_REQUEST_TOGGLE_STATUS = "status";
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // TOKEN_FIELD_CONST_H

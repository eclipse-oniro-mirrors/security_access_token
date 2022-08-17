/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef FIELD_CONST_H
#define FIELD_CONST_H

#include <string>

namespace OHOS {
namespace Security {
namespace AccessToken {
const std::string FIELD_TOKEN_ID = "token_id";
const std::string FIELD_USER_ID = "user_id";
const std::string FIELD_BUNDLE_NAME = "bundle_name";
const std::string FIELD_INST_INDEX = "inst_index";
const std::string FIELD_DLP_TYPE = "dlp_type";
const std::string FIELD_APP_ID = "app_id";
const std::string FIELD_DEVICE_ID = "device_id";
const std::string FIELD_APL = "apl";
const std::string FIELD_TOKEN_VERSION = "token_version";
const std::string FIELD_TOKEN_ATTR = "token_attr";
const std::string FIELD_PROCESS_NAME = "process_name";
const std::string FIELD_DCAP = "dcap";
const std::string FIELD_NATIVE_ACLS = "native_acls";
const std::string FIELD_PERMISSION_NAME = "permission_name";
const std::string FIELD_GRANT_MODE = "grant_mode";
const std::string FIELD_AVAILABLE_LEVEL = "available_level";
const std::string FIELD_PROVISION_ENABLE = "provision_enable";
const std::string FIELD_DISTRIBUTED_SCENE_ENABLE = "distributed_scene_enable";
const std::string FIELD_LABEL = "label";
const std::string FIELD_LABEL_ID = "label_id";
const std::string FIELD_DESCRIPTION = "description";
const std::string FIELD_DESCRIPTION_ID = "description_id";
const std::string FIELD_GRANT_STATE = "grant_state";
const std::string FIELD_GRANT_FLAG = "grant_flag";
const std::string FIELD_GRANT_IS_GENERAL = "is_general";

const std::string FIELD_OP_CODE = "op_code";
const std::string FIELD_STATUS = "status";
const std::string FIELD_TIMESTAMP = "timestamp";
const std::string FIELD_ACCESS_DURATION = "access_duration";
const std::string FIELD_ACCESS_COUNT = "access_count";
const std::string FIELD_REJECT_COUNT = "reject_count";

const std::string FIELD_TIMESTAMP_BEGIN = "timestamp_begin";
const std::string FIELD_TIMESTAMP_END = "timestamp_end";
const std::string FIELD_FLAG = "flag";
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // FIELD_CONST_H

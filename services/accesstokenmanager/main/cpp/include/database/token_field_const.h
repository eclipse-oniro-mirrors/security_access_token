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
    const static std::string FIELD_TOKEN_ID;
    const static std::string FIELD_USER_ID;
    const static std::string FIELD_BUNDLE_NAME;
    const static std::string FIELD_INST_INDEX;
    const static std::string FIELD_DLP_TYPE;
    const static std::string FIELD_APP_ID;
    const static std::string FIELD_DEVICE_ID;
    const static std::string FIELD_APL;
    const static std::string FIELD_TOKEN_VERSION;
    const static std::string FIELD_TOKEN_ATTR;
    const static std::string FIELD_PROCESS_NAME;
    const static std::string FIELD_DCAP;
    const static std::string FIELD_NATIVE_ACLS;
    const static std::string FIELD_PERMISSION_NAME;
    const static std::string FIELD_GRANT_MODE;
    const static std::string FIELD_AVAILABLE_LEVEL;
    const static std::string FIELD_PROVISION_ENABLE;
    const static std::string FIELD_DISTRIBUTED_SCENE_ENABLE;
    const static std::string FIELD_LABEL;
    const static std::string FIELD_LABEL_ID;
    const static std::string FIELD_DESCRIPTION;
    const static std::string FIELD_DESCRIPTION_ID;
    const static std::string FIELD_GRANT_STATE;
    const static std::string FIELD_GRANT_FLAG;
    const static std::string FIELD_GRANT_IS_GENERAL;
    const static std::string FIELD_API_VERSION;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // TOKEN_FIELD_CONST_H

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

#ifndef PRIVACY_SERVICE_IPC_INTERFACE_CODE_H
#define PRIVACY_SERVICE_IPC_INTERFACE_CODE_H

namespace OHOS {
namespace Security {
namespace AccessToken {
/* SAID:3505 */
enum class PrivacyInterfaceCode {
    ADD_PERMISSION_USED_RECORD = 0x0000,
    START_USING_PERMISSION,
    START_USING_PERMISSION_CALLBACK,
    STOP_USING_PERMISSION,
    DELETE_PERMISSION_USED_RECORDS,
    GET_PERMISSION_USED_RECORDS,
    GET_PERMISSION_USED_RECORDS_ASYNC,
    REGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK,
    UNREGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK,
    IS_ALLOWED_USING_PERMISSION,
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
    REGISTER_SEC_COMP_ENHANCE,
    UPDATE_SEC_COMP_ENHANCE,
    GET_SEC_COMP_ENHANCE,
    GET_SPECIAL_SEC_COMP_ENHANCE,
#endif
    GET_PERMISSION_USED_TYPE_INFOS,
    SET_MUTE_POLICY,
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // PRIVACY_SERVICE_IPC_INTERFACE_CODE_H

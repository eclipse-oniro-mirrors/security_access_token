
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
#ifndef ACCESS_TOKEN_ERROR_H
#define ACCESS_TOKEN_ERROR_H

namespace OHOS {
namespace Security {
namespace AccessToken {
enum AccessTokenError {
    ERR_NOT_HAVE_PERMISSION = 201,
    ERR_PARAM_INVALID = 12100001,
    ERR_TOKENID_NOT_EXIST,
    ERR_PERMISSION_NOT_EXIT,
    ERR_INTERFACE_NOT_USED_TOGETHER,
    ERR_EXCEEDED_MAXNUM_REGISTRATION_LIMIT,
    ERR_CROSS_DEVICE_NOT_SUPPORTED,
    ERR_PERMISSION_OPERATE_FAILED,
    ERR_SA_WORK_ABNORMAL,
    ERR_MALLOC_FAILED,
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif  // ACCESS_TOKEN_ERROR_H
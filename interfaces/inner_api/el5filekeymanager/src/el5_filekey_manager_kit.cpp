/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "el5_filekey_manager_kit.h"

#include "el5_filekey_manager_client.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
int32_t El5FilekeyManagerKit::AcquireAccess(DataLockType type)
{
    return El5FilekeyManagerClient::GetInstance().AcquireAccess(type);
}

int32_t El5FilekeyManagerKit::ReleaseAccess(DataLockType type)
{
    return El5FilekeyManagerClient::GetInstance().ReleaseAccess(type);
}

int32_t El5FilekeyManagerKit::GenerateAppKey(uint32_t uid, const std::string& bundleName, std::string& keyId)
{
    return El5FilekeyManagerClient::GetInstance().GenerateAppKey(uid, bundleName, keyId);
}

int32_t El5FilekeyManagerKit::DeleteAppKey(const std::string& bundleName, int32_t userId)
{
    return El5FilekeyManagerClient::GetInstance().DeleteAppKey(bundleName, userId);
}

int32_t El5FilekeyManagerKit::SetFilePathPolicy()
{
    return El5FilekeyManagerClient::GetInstance().SetFilePathPolicy();
}

int32_t El5FilekeyManagerKit::RegisterCallback(const sptr<El5FilekeyCallbackInterface> &callback)
{
    return El5FilekeyManagerClient::GetInstance().RegisterCallback(callback);
}

int32_t El5FilekeyManagerKit::GenerateGroupIDKey(uint32_t uid, const std::string &groupID, std::string &keyId)
{
    return El5FilekeyManagerClient::GetInstance().GenerateGroupIDKey(uid, groupID, keyId);
}

int32_t El5FilekeyManagerKit::DeleteGroupIDKey(uint32_t uid, const std::string &groupID)
{
    return El5FilekeyManagerClient::GetInstance().DeleteGroupIDKey(uid, groupID);
}

int32_t El5FilekeyManagerKit::QueryAppKeyState(DataLockType type)
{
    return El5FilekeyManagerClient::GetInstance().QueryAppKeyState(type);
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS

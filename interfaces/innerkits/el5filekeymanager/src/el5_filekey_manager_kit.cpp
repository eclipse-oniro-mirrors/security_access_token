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

int32_t El5FilekeyManagerKit::DeleteAppKey(const std::string& keyId)
{
    return El5FilekeyManagerClient::GetInstance().DeleteAppKey(keyId);
}

int32_t El5FilekeyManagerKit::GetUserAppKey(int32_t userId, std::vector<std::pair<int32_t, std::string>> &keyInfos)
{
    return El5FilekeyManagerClient::GetInstance().GetUserAppKey(userId, keyInfos);
}

int32_t El5FilekeyManagerKit::ChangeUserAppkeysLoadInfo(int32_t userId,
    std::vector<std::pair<std::string, bool>> &loadInfos)
{
    return El5FilekeyManagerClient::GetInstance().ChangeUserAppkeysLoadInfo(userId, loadInfos);
}

int32_t El5FilekeyManagerKit::SetFilePathPolicy()
{
    return El5FilekeyManagerClient::GetInstance().SetFilePathPolicy();
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS

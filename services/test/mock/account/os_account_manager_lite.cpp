/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "os_account_manager_lite.h"

namespace OHOS {
namespace {
int32_t g_mockForegroundLocalId = 0;
ErrCode g_mockForegroundLocalIdRet = ERR_OK;
int32_t g_mockForegroundSubProfileId = -1;
ErrCode g_mockForegroundSubProfileIdRet = ERR_OK;
int32_t g_mockSubProfileLocalId = 0;
ErrCode g_mockSubProfileLocalIdRet = ERR_OK;
int32_t g_mockSubProfileIndex = 0;
ErrCode g_mockSubProfileIndexRet = ERR_OK;
int32_t g_mockSubProfileId = 0;
ErrCode g_mockSubProfileIdRet = ERR_OK;
}

namespace AccountSA {
ErrCode OsAccountManagerLite::GetForegroundOsAccountLocalId(int32_t& localId)
{
    localId = g_mockForegroundLocalId;
    return g_mockForegroundLocalIdRet;
}

ErrCode OsAccountManagerLite::GetOsAccountForegroundSubProfileId(int32_t osAccountLocalId, int32_t& subProfileId)
{
    (void)osAccountLocalId;
    subProfileId = g_mockForegroundSubProfileId;
    return g_mockForegroundSubProfileIdRet;
}

ErrCode OsAccountManagerLite::GetOsAccountLocalIdForSubProfile(int32_t subProfileId, int32_t& localId)
{
    (void)subProfileId;
    localId = g_mockSubProfileLocalId;
    return g_mockSubProfileLocalIdRet;
}

ErrCode OsAccountManagerLite::GetOsAccountSubProfileIndex(
    int32_t osAccountLocalId, int32_t subProfileId, int32_t& appIndex)
{
    (void)osAccountLocalId;
    (void)subProfileId;
    appIndex = g_mockSubProfileIndex;
    return g_mockSubProfileIndexRet;
}

ErrCode OsAccountManagerLite::GetOsAccountSubProfileId(int32_t osAccountLocalId, int32_t appIndex,
    int32_t& subProfileId)
{
    (void)osAccountLocalId;
    (void)appIndex;
    subProfileId = g_mockSubProfileId;
    return g_mockSubProfileIdRet;
}
} // namespace AccountSA

namespace Security {
namespace AccessToken {
void SetMockForegroundOsAccountLocalId(int32_t localId, int32_t ret)
{
    g_mockForegroundLocalId = localId;
    g_mockForegroundLocalIdRet = ret;
}

int32_t GetMockForegroundOsAccountLocalId()
{
    return g_mockForegroundLocalId;
}

void SetMockOsAccountForegroundSubProfileId(int32_t subProfileId, int32_t ret)
{
    g_mockForegroundSubProfileId = subProfileId;
    g_mockForegroundSubProfileIdRet = ret;
}

void SetMockOsAccountLocalIdForSubProfile(int32_t localId, int32_t ret)
{
    g_mockSubProfileLocalId = localId;
    g_mockSubProfileLocalIdRet = ret;
}

void SetMockOsAccountSubProfileIndex(int32_t appIndex, int32_t ret)
{
    g_mockSubProfileIndex = appIndex;
    g_mockSubProfileIndexRet = ret;
}

void SetMockOsAccountSubProfileId(int32_t subProfileId, int32_t ret)
{
    g_mockSubProfileId = subProfileId;
    g_mockSubProfileIdRet = ret;
}

void ResetMockOsAccountManagerLite()
{
    g_mockForegroundLocalId = 0;
    g_mockForegroundLocalIdRet = ERR_OK;
    g_mockForegroundSubProfileId = -1;
    g_mockForegroundSubProfileIdRet = ERR_OK;
    g_mockSubProfileLocalId = 0;
    g_mockSubProfileLocalIdRet = ERR_OK;
    g_mockSubProfileIndex = 0;
    g_mockSubProfileIndexRet = ERR_OK;
    g_mockSubProfileId = 0;
    g_mockSubProfileIdRet = ERR_OK;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

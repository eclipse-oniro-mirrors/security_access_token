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

#include <string>
#include <cstring>
#include <securec.h>
#include "constant.h"
#include "accesstoken_log.h"
#include "softbus_bus_center.h"

using namespace OHOS::Security::AccessToken;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "SoftBusCenterMock"};
static const int REG_COUNT_LIMIT = 10;
} // namespace
static int regCount_ = -1;

bool IsRegCountOK()
{
    return regCount_ >= 0 && regCount_ < REG_COUNT_LIMIT;
}

int32_t GetLocalNodeDeviceInfo(const char *pkgName, NodeBasicInfo *info)
{
    strcpy_s(info->deviceName, sizeof(info->deviceName), "local");
    strcpy_s(info->networkId, sizeof(info->networkId), "local");
    info->deviceTypeId = 1;
    ACCESSTOKEN_LOG_DEBUG(LABEL, "success, count: %{public}d", regCount_);
    return Constant::SUCCESS;
}

int32_t GetNodeKeyInfo(const char *pkgName, const char *networkId, NodeDeviceInfoKey key, uint8_t *info,
    int32_t infoLen)
{
    if (networkId == nullptr || networkId[0] == '\0') {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "failure, invalid networkId, pkg name: %{public}s", pkgName);
        return Constant::FAILURE;
    }

    if (key == NodeDeviceInfoKey::NODE_KEY_UDID) {
        std::string temp = networkId;
        temp += ":udid-001";
        strncpy_s(reinterpret_cast<char *>(info), infoLen, temp.c_str(), temp.length());
        infoLen = temp.length();
    }
    if (key == NodeDeviceInfoKey::NODE_KEY_UUID) {
        std::string temp = networkId;
        temp += ":uuid-001";
        strncpy_s(reinterpret_cast<char *>(info), infoLen, temp.c_str(), temp.length());
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "success, count: %{public}d, id: %{public}s", regCount_, info);
    return Constant::SUCCESS;
}

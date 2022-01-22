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
#include "soft_bus_manager.h"

#include <securec.h>

#include "accesstoken.h"
#include "softbus_bus_center.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "SoftBusManager"};
}

namespace {
static const SessionAttribute SESSION_ATTR = {.dataType = TYPE_BYTES};

static const int REASON_EXIST = -3;
static const int OPENSESSION_RETRY_TIMES = 100;
static const int OPENSESSION_RETRY_INTERVAL_MS = 100;
static const int CREAT_SERVER_RETRY_INTERVAL_MS = 1000;
} // namespace

const std::string SoftBusManager::ACCESS_TOKEN_PACKAGE_NAME = "ohos.security.distributed_access_token";
const std::string SoftBusManager::SESSION_NAME = "ohos.security.atm_channel";

SoftBusManager::SoftBusManager() : isSoftBusServiceBindSuccess_(false), inited_(false), mutex_()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SoftBusManager()");
}

SoftBusManager::~SoftBusManager()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "~SoftBusManager()");
}

SoftBusManager &SoftBusManager::GetInstance()
{
    static SoftBusManager instance;
    return instance;
}

int SoftBusManager::OnSessionOpend(int sessionId, int result)
{
    if (result != 0) {
        ACCESSTOKEN_LOG_INFO(LABEL, "session is open failed, result %{public}d", result);
        return RET_FAILED;
    }
    SoftBusManager::GetInstance().ModifySessionStatus(sessionId);
    ACCESSTOKEN_LOG_INFO(LABEL, "session is open");
    return 0;
}

void SoftBusManager::OnSessionClosed(int sessionId)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "session is closed");
}

void SoftBusManager::OnBytesReceived(int sessionId, const void *data, unsigned int dataLen)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "session receive data.");
}

void SoftBusManager::OnMessageReceived(int sessionId, const void *data, unsigned int dataLen)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "session receive message.");
}

bool SoftBusManager::IsSessionOpen(int sessionId)
{
    Utils::UniqueReadGuard<Utils::RWLock> idGuard(this->sessIdLock_);
    if (sessOpenSet_.count(sessionId) == 0) {
        return true;
    }
    return false;
}

void SoftBusManager::ModifySessionStatus(int sessionId)
{
    Utils::UniqueWriteGuard<Utils::RWLock> idGuard(this->sessIdLock_);
    if (sessOpenSet_.count(sessionId) > 0) {
        sessOpenSet_.erase(sessionId);
    }
}

void SoftBusManager::SetSessionWaitingOpen(int sessionId)
{
    Utils::UniqueWriteGuard<Utils::RWLock> idGuard(this->sessIdLock_);
    sessOpenSet_.insert(sessionId);
}

void SoftBusManager::Initialize()
{
    bool inited = false;
    // cas failed means already inited.
    if (!inited_.compare_exchange_strong(inited, true)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "already initialized, skip");
        return;
    }

    while (1) {
        std::unique_lock<std::mutex> lock(mutex_);
        // register session listener
        ISessionListener sessionListener;
        sessionListener.OnSessionOpened = SoftBusManager::OnSessionOpend;
        sessionListener.OnSessionClosed = SoftBusManager::OnSessionClosed;
        sessionListener.OnBytesReceived = SoftBusManager::OnBytesReceived;
        sessionListener.OnMessageReceived = SoftBusManager::OnMessageReceived;

        int ret = ::CreateSessionServer(ACCESS_TOKEN_PACKAGE_NAME.c_str(), SESSION_NAME.c_str(), &sessionListener);
        ACCESSTOKEN_LOG_INFO(LABEL, "Initialize: createSessionServer, result: %{public}d", ret);
        // REASON_EXIST
        if ((ret != 0) && (ret != REASON_EXIST)) {
            auto sleepTime = std::chrono::milliseconds(CREAT_SERVER_RETRY_INTERVAL_MS);
            std::this_thread::sleep_for(sleepTime);
            continue;
        }
        isSoftBusServiceBindSuccess_ = true;
        break;
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "Initialize thread started");
}

void SoftBusManager::Destroy()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "destroy, init: %{public}d, isSoftBusServiceBindSuccess: %{public}d", inited_.load(),
        isSoftBusServiceBindSuccess_);

    if (inited_.load() == false) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "not inited, skip");
        return;
    }

    std::unique_lock<std::mutex> lock(mutex_);
    if (inited_.load() == false) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "not inited, skip");
        return;
    }

    if (isSoftBusServiceBindSuccess_) {
        int32_t ret = ::RemoveSessionServer(ACCESS_TOKEN_PACKAGE_NAME.c_str(), SESSION_NAME.c_str());
        ACCESSTOKEN_LOG_ERROR(LABEL, "destroy, RemoveSessionServer: %{public}d", ret);
        isSoftBusServiceBindSuccess_ = false;
    }

    inited_.store(false);

    ACCESSTOKEN_LOG_DEBUG(LABEL, "destroy, done");
}

int32_t SoftBusManager::SendRequest()
{
    NodeBasicInfo *info = nullptr;
    int32_t infoNum;
    int ret = GetAllNodeDeviceInfo(ACCESS_TOKEN_PACKAGE_NAME.c_str(), &info, &infoNum);
    if (ret != 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "can not get node device");
        return RET_FAILED;
    }

    // async open session, should waitting for OnSessionOpened event.
    int sessionId = ::OpenSession(SESSION_NAME.c_str(), SESSION_NAME.c_str(), info[0].networkId,
        "0", &SESSION_ATTR);
    if (sessionId < 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "open session failed");
        return RET_FAILED;
    }

    SetSessionWaitingOpen(sessionId);

    // wait session opening
    int retryTimes = 0;
    int logSpan = 10;
    auto sleepTime = std::chrono::milliseconds(OPENSESSION_RETRY_INTERVAL_MS);
    bool isOpen = false;
    while (retryTimes++ < OPENSESSION_RETRY_TIMES) {
        if (!IsSessionOpen(sessionId)) {
            std::this_thread::sleep_for(sleepTime);
            if (retryTimes % logSpan == 0) {
                ACCESSTOKEN_LOG_INFO(LABEL, "openSession, waitting for: %{public}d ms",
                    retryTimes * OPENSESSION_RETRY_INTERVAL_MS);
            }
            continue;
        }
        isOpen = true;
        break;
    }
    int cmd = 0;
    ret = ::SendBytes(sessionId, &cmd, sizeof(int));
    if (ret != 0) {
        ::CloseSession(sessionId);
        ACCESSTOKEN_LOG_ERROR(LABEL, "send cmd failed ret = %{public}d", ret);
        return RET_FAILED;
    }
    ::CloseSession(sessionId);
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

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
#include "constant_common.h"
#include "device_info_manager.h"
#include "softbus_bus_center.h"
#include "dm_device_info.h"
#include "remote_command_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "SoftBusManager"};
}
namespace {
static const std::string SESSION_GROUP_ID = "atm_dsoftbus_session_group_id";
static const SessionAttribute SESSION_ATTR = {.dataType = TYPE_BYTES};

static const int REASON_EXIST = -3;
static const int OPENSESSION_RETRY_TIMES = 10 * 3;
static const int OPENSESSION_RETRY_INTERVAL_MS = 100;
static const int UDID_MAX_LENGTH = 128; // udid/uuid max length
} // namespace

const std::string SoftBusManager::TOKEN_SYNC_PACKAGE_NAME = "ohos.security.distributed_access_token";
const std::string SoftBusManager::SESSION_NAME = "ohos.security.atm_channel";

SoftBusManager::SoftBusManager() : isSoftBusServiceBindSuccess_(false), inited_(false), mutex_(), fulfillMutex_()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "SoftBusManager()");
}

SoftBusManager::~SoftBusManager()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "~SoftBusManager()");
}

SoftBusManager &SoftBusManager::GetInstance()
{
    static SoftBusManager instance;
    return instance;
}

int SoftBusManager::AddTrustedDeviceInfo()
{
    std::string packageName = TOKEN_SYNC_PACKAGE_NAME;
    std::string extra = "";
    std::vector<DistributedHardware::DmDeviceInfo> deviceList;

    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetTrustedDeviceList(packageName,
        extra, deviceList);
    if (ret != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "AddTrustedDeviceInfo: GetTrustedDeviceList error, result: %{public}d", ret);
        return Constant::FAILURE;
    }

    for (const DistributedHardware::DmDeviceInfo& device : deviceList) {
        std::string uuid = GetUuidByNodeId(device.networkId);
        std::string udid = GetUdidByNodeId(device.networkId);
        if (uuid.empty() || udid.empty()) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "uuid = %{public}s, udid = %{public}s, uuid or udid is empty, abort.",
                uuid.c_str(), ConstantCommon::EncryptDevId(udid).c_str());
            continue;
        }

        DeviceInfoManager::GetInstance().AddDeviceInfo(device.networkId, uuid, udid, device.deviceName,
            std::to_string(device.deviceTypeId));
        RemoteCommandManager::GetInstance().NotifyDeviceOnline(udid);
    }

    return Constant::SUCCESS;
}

int SoftBusManager::DeviceInit()
{
    std::string packageName = TOKEN_SYNC_PACKAGE_NAME;
    std::shared_ptr<MyDmInitCallback> ptrDmInitCallback = std::make_shared<MyDmInitCallback>();

    int ret = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(packageName, ptrDmInitCallback);
    if (ret != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Initialize: InitDeviceManager error, result: %{public}d", ret);
        return ret;
    }

    ret = AddTrustedDeviceInfo();
    if (ret != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Initialize: AddTrustedDeviceInfo error, result: %{public}d", ret);
        return ret;
    }

    std::string extra = "";
    std::shared_ptr<SoftBusDeviceConnectionListener> ptrDeviceStateCallback =
        std::make_shared<SoftBusDeviceConnectionListener>();
    ret = DistributedHardware::DeviceManager::GetInstance().RegisterDevStateCallback(packageName, extra,
        ptrDeviceStateCallback);
    if (ret != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Initialize: RegisterDevStateCallback error, result: %{public}d", ret);
        return ret;
    }

    return ERR_OK;
}

int SoftBusManager::SessionInit()
{
    // register session listener
    ISessionListener sessionListener;
    sessionListener.OnSessionOpened = SoftBusSessionListener::OnSessionOpened;
    sessionListener.OnSessionClosed = SoftBusSessionListener::OnSessionClosed;
    sessionListener.OnBytesReceived = SoftBusSessionListener::OnBytesReceived;
    sessionListener.OnMessageReceived = SoftBusSessionListener::OnMessageReceived;

    int ret = ::CreateSessionServer(TOKEN_SYNC_PACKAGE_NAME.c_str(), SESSION_NAME.c_str(), &sessionListener);
    ACCESSTOKEN_LOG_INFO(LABEL, "Initialize: createSessionServer, result: %{public}d", ret);
    // REASON_EXIST
    if ((ret != Constant::SUCCESS) && (ret != REASON_EXIST)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Initialize: CreateSessionServer error, result: %{public}d", ret);
        return ret;
    }

    return ERR_OK;
}

void SoftBusManager::Initialize()
{
    bool inited = false;
    // cas failed means already inited.
    if (!inited_.compare_exchange_strong(inited, true)) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "already initialized, skip");
        return;
    }

    std::function<void()> runner = [&]() {
        auto sleepTime = std::chrono::milliseconds(1000);
        while (1) {
            std::unique_lock<std::mutex> lock(mutex_);
            
            int ret = DeviceInit();
            if (ret != ERR_OK) {
                std::this_thread::sleep_for(sleepTime);
                continue;
            }

            ret = SessionInit();
            if (ret != ERR_OK) {
                std::this_thread::sleep_for(sleepTime);
                continue;
            }

            isSoftBusServiceBindSuccess_ = true;
            this->FulfillLocalDeviceInfo();
            return;
        }
    };

    std::thread initThread(runner);
    initThread.detach();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Initialize thread started");
}

void SoftBusManager::Destroy()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "destroy, init: %{public}d, isSoftBusServiceBindSuccess: %{public}d", inited_.load(),
        isSoftBusServiceBindSuccess_);

    if (!inited_.load()) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "not inited, skip");
        return;
    }

    std::unique_lock<std::mutex> lock(mutex_);
    if (!inited_.load()) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "not inited, skip");
        return;
    }

    if (isSoftBusServiceBindSuccess_) {
        int32_t ret = ::RemoveSessionServer(TOKEN_SYNC_PACKAGE_NAME.c_str(), SESSION_NAME.c_str());
        ACCESSTOKEN_LOG_DEBUG(LABEL, "destroy, RemoveSessionServer: %{public}d", ret);
        isSoftBusServiceBindSuccess_ = false;
    }

    std::string packageName = TOKEN_SYNC_PACKAGE_NAME;
    int ret = DistributedHardware::DeviceManager::GetInstance().UnRegisterDevStateCallback(packageName);
    if (ret != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UnRegisterDevStateCallback failed, code: %{public}d", ret);
    }
    ret = DistributedHardware::DeviceManager::GetInstance().UnInitDeviceManager(packageName);
    if (ret != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UnInitDeviceManager failed, code: %{public}d", ret);
    }

    inited_.store(false);

    ACCESSTOKEN_LOG_DEBUG(LABEL, "destroy, done");
}

int32_t SoftBusManager::OpenSession(const std::string &deviceId)
{
#ifdef DEBUG_API_PERFORMANCE
    ACCESSTOKEN_LOG_INFO(LABEL, "api_performance:start open session");
#endif

    DeviceInfo info;
    bool result = DeviceInfoManager::GetInstance().GetDeviceInfo(deviceId, DeviceIdType::UNKNOWN, info);
    if (!result) {
        ACCESSTOKEN_LOG_WARN(LABEL, "device info notfound for deviceId %{public}s",
            ConstantCommon::EncryptDevId(deviceId).c_str());
        return Constant::FAILURE;
    }
    std::string networkId = info.deviceId.networkId;
    ACCESSTOKEN_LOG_INFO(LABEL, "openSession, networkId: %{public}s", networkId.c_str());

    // async open session, should waitting for OnSessionOpened event.
    int sessionId = ::OpenSession(SESSION_NAME.c_str(), SESSION_NAME.c_str(), networkId.c_str(),
        SESSION_GROUP_ID.c_str(), &SESSION_ATTR);

    ACCESSTOKEN_LOG_DEBUG(LABEL, "async open session");

    // wait session opening
    int retryTimes = 0;
    int logSpan = 10;
    auto sleepTime = std::chrono::milliseconds(OPENSESSION_RETRY_INTERVAL_MS);
    while (retryTimes++ < OPENSESSION_RETRY_TIMES) {
        if (SoftBusSessionListener::GetSessionState(sessionId) < 0) {
            std::this_thread::sleep_for(sleepTime);
            if (retryTimes % logSpan == 0) {
                ACCESSTOKEN_LOG_INFO(LABEL, "openSession, waitting for: %{public}d ms",
                    retryTimes * OPENSESSION_RETRY_INTERVAL_MS);
            }
            continue;
        }
        break;
    }
#ifdef DEBUG_API_PERFORMANCE
    ACCESSTOKEN_LOG_INFO(LABEL, "api_performance:start open session success");
#endif
    int64_t state = SoftBusSessionListener::GetSessionState(sessionId);
    if (state < 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "openSession, timeout, session: %{public}" PRId64, state);
        return Constant::FAILURE;
    }

    SoftBusSessionListener::DeleteSessionIdFromMap(sessionId);

    ACCESSTOKEN_LOG_DEBUG(LABEL, "openSession, succeed, session: %{public}" PRId64, state);
    return sessionId;
}

int SoftBusManager::CloseSession(int sessionId)
{
    if (sessionId < 0) {
        ACCESSTOKEN_LOG_INFO(LABEL, "closeSession: session is invalid");
        return Constant::FAILURE;
    }

    ::CloseSession(sessionId);
    ACCESSTOKEN_LOG_INFO(LABEL, "closeSession ");
    return Constant::SUCCESS;
}

std::string SoftBusManager::GetUniversallyUniqueIdByNodeId(const std::string &nodeId)
{
    if (!DataValidator::IsDeviceIdValid(nodeId)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid nodeId: %{public}s", ConstantCommon::EncryptDevId(nodeId).c_str());
        return "";
    }

    std::string uuid = GetUuidByNodeId(nodeId);
    if (uuid.empty()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "softbus return null or empty string");
        return "";
    }

    DeviceInfo info;
    bool result = DeviceInfoManager::GetInstance().GetDeviceInfo(uuid, DeviceIdType::UNIVERSALLY_UNIQUE_ID, info);
    if (!result) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "local device info not found for uuid %{public}s", uuid.c_str());
    } else {
        std::string dimUuid = info.deviceId.universallyUniqueId;
        if (uuid == dimUuid) {
            // refresh cache
            std::function<void()> fulfillDeviceInfo = std::bind(&SoftBusManager::FulfillLocalDeviceInfo, this);
            std::thread fulfill(fulfillDeviceInfo);
            fulfill.detach();
        }
    }

    return uuid;
}

std::string SoftBusManager::GetUniqueDeviceIdByNodeId(const std::string &nodeId)
{
    if (!DataValidator::IsDeviceIdValid(nodeId)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid nodeId: %{public}s", ConstantCommon::EncryptDevId(nodeId).c_str());
        return "";
    }
    std::string udid = GetUdidByNodeId(nodeId);
    if (udid.empty()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "softbus return null or empty string: %{public}s",
            ConstantCommon::EncryptDevId(udid).c_str());
        return "";
    }
    std::string localUdid = ConstantCommon::GetLocalDeviceId();
    if (udid == localUdid) {
        // refresh cache
        std::function<void()> fulfillDeviceInfo = std::bind(&SoftBusManager::FulfillLocalDeviceInfo, this);
        std::thread fulfill(fulfillDeviceInfo);
        fulfill.detach();
    }
    return udid;
}

std::string SoftBusManager::GetUuidByNodeId(const std::string &nodeId) const
{
    uint8_t *info = new (std::nothrow) uint8_t[UDID_MAX_LENGTH + 1];
    if (info == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "no enough memory: %{public}d", UDID_MAX_LENGTH);
        return "";
    }
    (void)memset_s(info, UDID_MAX_LENGTH + 1, 0, UDID_MAX_LENGTH + 1);
    int32_t ret = ::GetNodeKeyInfo(TOKEN_SYNC_PACKAGE_NAME.c_str(), nodeId.c_str(),
        NodeDeviceInfoKey::NODE_KEY_UUID, info, UDID_MAX_LENGTH);
    if (ret != Constant::SUCCESS) {
        delete[] info;
        ACCESSTOKEN_LOG_WARN(LABEL, "GetNodeKeyInfo error, return code: %{public}d", ret);
        return "";
    }
    std::string uuid(reinterpret_cast<char *>(info));
    delete[] info;
    ACCESSTOKEN_LOG_DEBUG(LABEL, "call softbus finished. nodeId(in): %{public}s, uuid: %{public}s",
        ConstantCommon::EncryptDevId(nodeId).c_str(), uuid.c_str());
    return uuid;
}

std::string SoftBusManager::GetUdidByNodeId(const std::string &nodeId) const
{
    uint8_t *info = new (std::nothrow) uint8_t[UDID_MAX_LENGTH + 1];
    if (info == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "no enough memory: %{public}d", UDID_MAX_LENGTH);
        return "";
    }
    (void)memset_s(info, UDID_MAX_LENGTH + 1, 0, UDID_MAX_LENGTH + 1);
    int32_t ret = ::GetNodeKeyInfo(TOKEN_SYNC_PACKAGE_NAME.c_str(), nodeId.c_str(),
        NodeDeviceInfoKey::NODE_KEY_UDID, info, UDID_MAX_LENGTH);
    if (ret != Constant::SUCCESS) {
        delete[] info;
        ACCESSTOKEN_LOG_WARN(LABEL, "GetNodeKeyInfo error, code: %{public}d", ret);
        return "";
    }
    std::string udid(reinterpret_cast<char *>(info));
    delete[] info;
    ACCESSTOKEN_LOG_DEBUG(LABEL, "call softbus finished: nodeId(in): %{public}s",
        ConstantCommon::EncryptDevId(nodeId).c_str());
    return udid;
}

int SoftBusManager::FulfillLocalDeviceInfo()
{
    // repeated task will just skip
    if (!fulfillMutex_.try_lock()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "FulfillLocalDeviceInfo already running, skip.");
        return Constant::SUCCESS;
    }

    NodeBasicInfo info;
    int32_t ret = ::GetLocalNodeDeviceInfo(TOKEN_SYNC_PACKAGE_NAME.c_str(), &info);
    if (ret != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetLocalNodeDeviceInfo error");
        fulfillMutex_.unlock();
        return Constant::FAILURE;
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "call softbus finished, type:%{public}d", info.deviceTypeId);

    std::string uuid = GetUuidByNodeId(info.networkId);
    std::string udid = GetUdidByNodeId(info.networkId);
    if (uuid.empty() || udid.empty()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "FulfillLocalDeviceInfo: uuid or udid is empty, abort.");
        fulfillMutex_.unlock();
        return Constant::FAILURE;
    }

    DeviceInfoManager::GetInstance().AddDeviceInfo(info.networkId, uuid, udid, info.deviceName,
        std::to_string(info.deviceTypeId));
    ACCESSTOKEN_LOG_DEBUG(LABEL, "AddDeviceInfo finished");

    fulfillMutex_.unlock();
    return Constant::SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

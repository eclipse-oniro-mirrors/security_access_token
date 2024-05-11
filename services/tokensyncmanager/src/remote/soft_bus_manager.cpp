/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include <thread>
#include <pthread.h>

#include "accesstoken_config_policy.h"
#include "accesstoken_log.h"
#include "constant.h"
#include "constant_common.h"
#include "device_info_manager.h"
#include "dm_device_info.h"
#include "ipc_skeleton.h"
#include "remote_command_manager.h"
#include "softbus_bus_center.h"
#include "soft_bus_device_connection_listener.h"
#include "soft_bus_socket_listener.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "SoftBusManager"};
static constexpr int32_t DEFAULT_SEND_REQUEST_REPEAT_TIMES = 5;
}
namespace {
static const int UDID_MAX_LENGTH = 128; // udid/uuid max length
static const int MAX_PTHREAD_NAME_LEN = 15; // pthread name max length

static const std::string TOKEN_SYNC_PACKAGE_NAME = "ohos.security.distributed_access_token";
static const std::string TOKEN_SYNC_SOCKET_NAME = "ohos.security.atm_channel.";

static const uint32_t SOCKET_NAME_MAX_LEN = 256;
static const uint32_t QOS_LEN = 3;
static const int32_t MIN_BW = 64 * 1024; // 64k
static const int32_t MAX_LATENCY = 10000; // 10s
static const int32_t MIN_LATENCY = 2000; // 2s

static const int32_t ERROR_TRANSFORM_STRING_TO_CHAR = -1;
static const int32_t ERROR_CREATE_SOCKET_FAIL = -2;
static const int32_t ERROR_CREATE_LISTENER_FAIL = -3;
static const int32_t ERROR_CLIENT_HAS_BIND_ALREADY = -4;

static const int32_t BIND_SERVICE_MAX_RETRY_TIMES = 10;
static const int32_t BIND_SERVICE_SLEEP_TIMES_MS = 100; // 0.1s
std::recursive_mutex g_instanceMutex;
} // namespace

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
    static SoftBusManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new SoftBusManager();
        }
    }
    return *instance;
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
                ConstantCommon::EncryptDevId(uuid).c_str(), ConstantCommon::EncryptDevId(udid).c_str());
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

bool SoftBusManager::CheckAndCopyStr(char* dest, uint32_t destLen, const std::string& src)
{
    if (destLen < src.length() + 1) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid src length");
        return false;
    }
    if (strcpy_s(dest, destLen, src.c_str()) != EOK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid src");
        return false;
    }
    return true;
}

int32_t SoftBusManager::ServiceSocketInit()
{
    std::string serviceName = TOKEN_SYNC_SOCKET_NAME + "service";
    char name[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(name, SOCKET_NAME_MAX_LEN, serviceName)) {
        return ERROR_TRANSFORM_STRING_TO_CHAR;
    }

    char pkgName[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(pkgName, SOCKET_NAME_MAX_LEN, TOKEN_SYNC_PACKAGE_NAME)) {
        return ERROR_TRANSFORM_STRING_TO_CHAR;
    }

    SocketInfo info = {
        .name = name,
        .pkgName = pkgName,
        .dataType = DATA_TYPE_BYTES
    };
    int32_t ret = ::Socket(info); // create service socket id
    if (ret <= Constant::INVALID_SOCKET_FD) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "create service socket faild, ret is %{public}d.", ret);
        return ERROR_CREATE_SOCKET_FAIL;
    } else {
        socketFd_ = ret;
        ACCESSTOKEN_LOG_DEBUG(LABEL, "create service socket[%{public}d] success.", socketFd_);
    }

    // set service qos, no need to regist OnQos now, regist it
    QosTV serverQos[] = {
        { .qos = QOS_TYPE_MIN_BW,      .value = MIN_BW },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = MAX_LATENCY },
        { .qos = QOS_TYPE_MIN_LATENCY, .value = MIN_LATENCY },
    };

    ISocketListener listener;
    listener.OnBind = SoftBusSocketListener::OnBind; // only service may receive OnBind
    listener.OnShutdown = SoftBusSocketListener::OnShutdown;
    listener.OnBytes = SoftBusSocketListener::OnClientBytes;

    ret = ::Listen(socketFd_, serverQos, QOS_LEN, &listener);
    if (ret != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "create listener failed, ret is %{public}d.", ret);
        return ERROR_CREATE_LISTENER_FAIL;
    } else {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "create listener success.");
    }

    return ERR_OK;
}

int32_t SoftBusManager::GetRepeatTimes()
{
    // this value only set in service OnStart, no need lock when set and get
    return sendRequestRepeatTimes_;
}

void SoftBusManager::SetDefaultConfigValue()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "no config file or config file is not valid, use default values");

    sendRequestRepeatTimes_ = DEFAULT_SEND_REQUEST_REPEAT_TIMES;
}

void SoftBusManager::GetConfigValue()
{
    AccessTokenConfigPolicy policy;
    AccessTokenConfigValue value;
    if (policy.GetConfigValue(ServiceType::TOKENSYNC_SERVICE, value)) {
        sendRequestRepeatTimes_ = value.tsConfig.sendRequestRepeatTimes;
    } else {
        SetDefaultConfigValue();
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "sendRequestRepeatTimes_ is %{public}d.", sendRequestRepeatTimes_);
}

void SoftBusManager::Initialize()
{
    bool inited = false;
    // cas failed means already inited.
    if (!inited_.compare_exchange_strong(inited, true)) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "already initialized, skip");
        return;
    }

    GetConfigValue();

    std::function<void()> runner = [&]() {
        std::string name = "SoftBusMagInit";
        pthread_setname_np(pthread_self(), name.substr(0, MAX_PTHREAD_NAME_LEN).c_str());
        auto sleepTime = std::chrono::milliseconds(1000);
        while (1) {
            std::unique_lock<std::mutex> lock(mutex_);
            
            int ret = DeviceInit();
            if (ret != ERR_OK) {
                std::this_thread::sleep_for(sleepTime);
                continue;
            }

            ret = ServiceSocketInit();
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
        if (socketFd_ > Constant::INVALID_SOCKET_FD) {
            ::Shutdown(socketFd_);
        }

        ACCESSTOKEN_LOG_DEBUG(LABEL, "Destroy service socket.");

        SoftBusSocketListener::CleanUpAllBindSocket();

        ACCESSTOKEN_LOG_DEBUG(LABEL, "Destroy client socket.");

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

int32_t SoftBusManager::InitSocketAndListener(const std::string& networkId, ISocketListener& listener)
{
    std::string clientName = TOKEN_SYNC_SOCKET_NAME + networkId;
    char name[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(name, SOCKET_NAME_MAX_LEN, clientName)) {
        return ERROR_TRANSFORM_STRING_TO_CHAR;
    }

    std::string serviceName = TOKEN_SYNC_SOCKET_NAME + "service";
    char peerName[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(peerName, SOCKET_NAME_MAX_LEN, serviceName)) {
        return ERROR_TRANSFORM_STRING_TO_CHAR;
    }

    char peerNetworkId[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(peerNetworkId, SOCKET_NAME_MAX_LEN, networkId)) {
        return ERROR_TRANSFORM_STRING_TO_CHAR;
    }

    char pkgName[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(pkgName, SOCKET_NAME_MAX_LEN, TOKEN_SYNC_PACKAGE_NAME)) {
        return ERROR_TRANSFORM_STRING_TO_CHAR;
    }

    SocketInfo info = {
        .name = name,
        .peerName = peerName,
        .peerNetworkId = peerNetworkId,
        .pkgName = pkgName,
        .dataType = DATA_TYPE_BYTES
    };

    listener.OnShutdown = SoftBusSocketListener::OnShutdown;
    listener.OnBytes = SoftBusSocketListener::OnServiceBytes;
    listener.OnQos = SoftBusSocketListener::OnQos; // only client may receive OnQos

    return ::Socket(info);
}

int32_t SoftBusManager::BindService(const std::string &deviceId)
{
#ifdef DEBUG_API_PERFORMANCE
    ACCESSTOKEN_LOG_INFO(LABEL, "api_performance:start bind service");
#endif

    DeviceInfo info;
    bool result = DeviceInfoManager::GetInstance().GetDeviceInfo(deviceId, DeviceIdType::UNKNOWN, info);
    if (!result) {
        ACCESSTOKEN_LOG_WARN(LABEL, "device info not found for deviceId %{public}s",
            ConstantCommon::EncryptDevId(deviceId).c_str());
        return Constant::FAILURE;
    }
    std::string networkId = info.deviceId.networkId;

    ISocketListener listener;
    int32_t socketFd = InitSocketAndListener(networkId, listener);
    if (socketFd_ <= Constant::INVALID_SOCKET_FD) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "create client socket faild.");
        return ERROR_CREATE_SOCKET_FAIL;
    }

    {
        std::lock_guard<std::mutex> guard(clientSocketMutex_);
        auto iter = clientSocketMap_.find(socketFd);
        if (iter == clientSocketMap_.end()) {
            clientSocketMap_.insert(std::pair<int32_t, std::string>(socketFd, networkId));
        } else {
            ACCESSTOKEN_LOG_ERROR(LABEL, "client socket has bind already");
            return ERROR_CLIENT_HAS_BIND_ALREADY;
        }
    }

    QosTV clientQos[] = {
        { .qos = QOS_TYPE_MIN_BW,      .value = MIN_BW },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = MAX_LATENCY },
        { .qos = QOS_TYPE_MIN_LATENCY, .value = MIN_LATENCY },
    };

    AccessTokenID firstCaller = IPCSkeleton::GetFirstTokenID();
    SetFirstCallerTokenID(firstCaller);
    ACCESSTOKEN_LOG_INFO(LABEL, "Bind service and setFirstCaller %{public}u.", firstCaller);

    // retry 10 times or bind success
    int32_t retryTimes = 0;
    auto sleepTime = std::chrono::milliseconds(BIND_SERVICE_SLEEP_TIMES_MS);
    while (retryTimes < BIND_SERVICE_MAX_RETRY_TIMES) {
        int32_t res = ::Bind(socketFd, clientQos, QOS_LEN, &listener);
        if (res != Constant::SUCCESS) {
            std::this_thread::sleep_for(sleepTime);
            retryTimes++;
            continue;
        }
        break;
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "Bind service succeed, socketFd is %{public}d.", socketFd);
    return socketFd;
}

int SoftBusManager::CloseSocket(int socketFd)
{
    if (socketFd <= Constant::INVALID_SOCKET_FD) {
        ACCESSTOKEN_LOG_INFO(LABEL, "socket is invalid");
        return Constant::FAILURE;
    }

    ::Shutdown(socketFd);

    std::lock_guard<std::mutex> guard(clientSocketMutex_);
    auto iter = clientSocketMap_.find(socketFd);
    if (iter != clientSocketMap_.end()) {
        clientSocketMap_.erase(iter);
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "close socket");

    return Constant::SUCCESS;
}

bool SoftBusManager::GetNetworkIdBySocket(const int32_t socket, std::string& networkId)
{
    std::lock_guard<std::mutex> guard(clientSocketMutex_);
    auto iter = clientSocketMap_.find(socket);
    if (iter != clientSocketMap_.end()) {
        networkId = iter->second;
        return true;
    }
    return false;
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
        ACCESSTOKEN_LOG_DEBUG(LABEL, "local device info not found for uuid %{public}s",
            ConstantCommon::EncryptDevId(uuid).c_str());
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
        ConstantCommon::EncryptDevId(nodeId).c_str(), ConstantCommon::EncryptDevId(uuid).c_str());
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

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

#include "accesstoken_log.h"
#include "config_policy_loader.h"
#include "constant.h"
#include "constant_common.h"
#include "device_info_manager.h"
#include "device_manager.h"
#include "ipc_skeleton.h"
#include "libraryloader.h"
#include "remote_command_manager.h"
#include "soft_bus_device_connection_listener.h"
#include "soft_bus_socket_listener.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t DEFAULT_SEND_REQUEST_REPEAT_TIMES = 5;
static const int MAX_PTHREAD_NAME_LEN = 15; // pthread name max length

constexpr const char* TOKEN_SYNC_PACKAGE_NAME = "ohos.security.distributed_access_token";
constexpr const char* TOKEN_SYNC_SOCKET_NAME = "ohos.security.atm_channel.";
constexpr const char* TOKEN_SYNC_SERVICE_NAME = "ohos.security.atm_channel.service";

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
    LOGD(AT_DOMAIN, AT_TAG, "SoftBusManager()");
}

SoftBusManager::~SoftBusManager()
{
    LOGD(AT_DOMAIN, AT_TAG, "~SoftBusManager()");
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
        LOGE(AT_DOMAIN, AT_TAG, " GetTrustedDeviceList error, result: %{public}d", ret);
        return Constant::FAILURE;
    }

    for (const DistributedHardware::DmDeviceInfo& device : deviceList) {
        std::string uuid;
        std::string udid;
        DistributedHardware::DeviceManager::GetInstance().GetUuidByNetworkId(TOKEN_SYNC_PACKAGE_NAME, device.networkId,
            uuid);
        DistributedHardware::DeviceManager::GetInstance().GetUdidByNetworkId(TOKEN_SYNC_PACKAGE_NAME, device.networkId,
            udid);
        if (uuid.empty() || udid.empty()) {
            LOGE(AT_DOMAIN, AT_TAG,
                "Uuid = %{public}s, udid = %{public}s, uuid or udid is empty, abort.",
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
    std::shared_ptr<TokenSyncDmInitCallback> ptrDmInitCallback = std::make_shared<TokenSyncDmInitCallback>();

    int ret = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(packageName, ptrDmInitCallback);
    if (ret != ERR_OK) {
        LOGE(AT_DOMAIN, AT_TAG, "Initialize: InitDeviceManager error, result: %{public}d", ret);
        return ret;
    }

    ret = AddTrustedDeviceInfo();
    if (ret != ERR_OK) {
        LOGE(AT_DOMAIN, AT_TAG, "Initialize: AddTrustedDeviceInfo error, result: %{public}d", ret);
        return ret;
    }

    std::string extra = "";
    std::shared_ptr<SoftBusDeviceConnectionListener> ptrDeviceStateCallback =
        std::make_shared<SoftBusDeviceConnectionListener>();
    ret = DistributedHardware::DeviceManager::GetInstance().RegisterDevStateCallback(packageName, extra,
        ptrDeviceStateCallback);
    if (ret != ERR_OK) {
        LOGE(AT_DOMAIN, AT_TAG, "RegisterDevStateCallback error, result: %{public}d", ret);
        return ret;
    }

    return ERR_OK;
}

bool SoftBusManager::CheckAndCopyStr(char* dest, uint32_t destLen, const std::string& src)
{
    if (destLen < src.length() + 1) {
        LOGE(AT_DOMAIN, AT_TAG, "Invalid src length");
        return false;
    }
    if (strcpy_s(dest, destLen, src.c_str()) != EOK) {
        LOGE(AT_DOMAIN, AT_TAG, "Invalid src");
        return false;
    }
    return true;
}

int32_t SoftBusManager::ServiceSocketInit()
{
    char name[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(name, SOCKET_NAME_MAX_LEN, TOKEN_SYNC_SERVICE_NAME)) {
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
        LOGE(AT_DOMAIN, AT_TAG, "Create service socket faild, ret is %{public}d.", ret);
        return ERROR_CREATE_SOCKET_FAIL;
    } else {
        socketFd_ = ret;
        LOGD(AT_DOMAIN, AT_TAG, "Create service socket[%{public}d] success.", socketFd_);
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
        LOGE(AT_DOMAIN, AT_TAG, "Create listener failed, ret is %{public}d.", ret);
        return ERROR_CREATE_LISTENER_FAIL;
    } else {
        LOGD(AT_DOMAIN, AT_TAG, "Create listener success.");
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
    LOGI(AT_DOMAIN, AT_TAG, "No config file or config file is not valid, use default values");

    sendRequestRepeatTimes_ = DEFAULT_SEND_REQUEST_REPEAT_TIMES;
}

void SoftBusManager::GetConfigValue()
{
    LibraryLoader loader(CONFIG_POLICY_LIBPATH);
    ConfigPolicyLoaderInterface* policy = loader.GetObject<ConfigPolicyLoaderInterface>();
    if (policy == nullptr) {
        LOGE(AT_DOMAIN, AT_TAG, "Dlopen libaccesstoken_config_policy failed.");
        return;
    }
    AccessTokenConfigValue value;
    if (policy->GetConfigValue(ServiceType::TOKENSYNC_SERVICE, value)) {
        sendRequestRepeatTimes_ = value.tsConfig.sendRequestRepeatTimes == 0
            ? DEFAULT_SEND_REQUEST_REPEAT_TIMES : value.tsConfig.sendRequestRepeatTimes;
    } else {
        SetDefaultConfigValue();
    }

    LOGI(AT_DOMAIN, AT_TAG, "SendRequestRepeatTimes_ is %{public}d.", sendRequestRepeatTimes_);
}

void SoftBusManager::Initialize()
{
    bool inited = false;
    // cas failed means already inited.
    if (!inited_.compare_exchange_strong(inited, true)) {
        LOGD(AT_DOMAIN, AT_TAG, "Already initialized, skip");
        return;
    }

    GetConfigValue();

    std::function<void()> runner = [this]() {
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
    LOGD(AT_DOMAIN, AT_TAG, "Initialize thread started");
}

void SoftBusManager::Destroy()
{
    LOGD(AT_DOMAIN, AT_TAG,
        "Destroy: %{public}d, isSoftBusServiceBindSuccess: %{public}d", inited_.load(), isSoftBusServiceBindSuccess_);

    if (!inited_.load()) {
        LOGD(AT_DOMAIN, AT_TAG, "Not inited, skip");
        return;
    }

    std::unique_lock<std::mutex> lock(mutex_);
    if (!inited_.load()) {
        LOGD(AT_DOMAIN, AT_TAG, "Not inited, skip");
        return;
    }

    if (isSoftBusServiceBindSuccess_) {
        if (socketFd_ > Constant::INVALID_SOCKET_FD) {
            ::Shutdown(socketFd_);
        }

        LOGD(AT_DOMAIN, AT_TAG, "Destroy service socket.");

        SoftBusSocketListener::CleanUpAllBindSocket();

        LOGD(AT_DOMAIN, AT_TAG, "Destroy client socket.");

        isSoftBusServiceBindSuccess_ = false;
    }

    std::string packageName = TOKEN_SYNC_PACKAGE_NAME;
    int ret = DistributedHardware::DeviceManager::GetInstance().UnRegisterDevStateCallback(packageName);
    if (ret != ERR_OK) {
        LOGE(AT_DOMAIN, AT_TAG, "UnRegisterDevStateCallback failed, code: %{public}d", ret);
    }
    ret = DistributedHardware::DeviceManager::GetInstance().UnInitDeviceManager(packageName);
    if (ret != ERR_OK) {
        LOGE(AT_DOMAIN, AT_TAG, "UnInitDeviceManager failed, code: %{public}d", ret);
    }

    inited_.store(false);

    LOGD(AT_DOMAIN, AT_TAG, "Destroy, done");
}

int32_t SoftBusManager::InitSocketAndListener(const std::string& networkId, ISocketListener& listener)
{
    std::string clientName = TOKEN_SYNC_SOCKET_NAME + networkId;
    char name[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(name, SOCKET_NAME_MAX_LEN, clientName)) {
        return ERROR_TRANSFORM_STRING_TO_CHAR;
    }

    char peerName[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(peerName, SOCKET_NAME_MAX_LEN, TOKEN_SYNC_SERVICE_NAME)) {
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
    LOGI(AT_DOMAIN, AT_TAG, "Api_performance:start bind service");
#endif

    DeviceInfo info;
    bool result = DeviceInfoManager::GetInstance().GetDeviceInfo(deviceId, DeviceIdType::UNKNOWN, info);
    if (!result) {
        LOGW(AT_DOMAIN, AT_TAG, "Device info not found for deviceId %{public}s",
            ConstantCommon::EncryptDevId(deviceId).c_str());
        return Constant::FAILURE;
    }
    std::string networkId = info.deviceId.networkId;

    ISocketListener listener;
    int32_t socketFd = InitSocketAndListener(networkId, listener);
    if (socketFd_ <= Constant::INVALID_SOCKET_FD) {
        LOGE(AT_DOMAIN, AT_TAG, "Create client socket faild.");
        return ERROR_CREATE_SOCKET_FAIL;
    }

    {
        std::lock_guard<std::mutex> guard(clientSocketMutex_);
        auto iter = clientSocketMap_.find(socketFd);
        if (iter == clientSocketMap_.end()) {
            clientSocketMap_.insert(std::pair<int32_t, std::string>(socketFd, networkId));
        } else {
            LOGE(AT_DOMAIN, AT_TAG, "Client socket has bind already");
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
    LOGI(AT_DOMAIN, AT_TAG, "Bind service and setFirstCaller %{public}u.", firstCaller);

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

    LOGD(AT_DOMAIN, AT_TAG, "Bind service succeed, socketFd is %{public}d.", socketFd);
    return socketFd;
}

int SoftBusManager::CloseSocket(int socketFd)
{
    if (socketFd <= Constant::INVALID_SOCKET_FD) {
        LOGI(AT_DOMAIN, AT_TAG, "Socket is invalid");
        return Constant::FAILURE;
    }

    ::Shutdown(socketFd);

    std::lock_guard<std::mutex> guard(clientSocketMutex_);
    auto iter = clientSocketMap_.find(socketFd);
    if (iter != clientSocketMap_.end()) {
        clientSocketMap_.erase(iter);
    }

    LOGI(AT_DOMAIN, AT_TAG, "Close socket");

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

std::string SoftBusManager::GetUniversallyUniqueIdByNodeId(const std::string &networkId)
{
    if (!DataValidator::IsDeviceIdValid(networkId)) {
        LOGE(AT_DOMAIN, AT_TAG, "Invalid networkId, empty or size extends 256");
        return "";
    }

    std::string uuid;
    DistributedHardware::DeviceManager::GetInstance().GetUuidByNetworkId(TOKEN_SYNC_PACKAGE_NAME, networkId, uuid);
    if (uuid.empty()) {
        LOGE(AT_DOMAIN, AT_TAG, "Softbus return null or empty string");
        return "";
    }

    DeviceInfo info;
    bool result = DeviceInfoManager::GetInstance().GetDeviceInfo(uuid, DeviceIdType::UNIVERSALLY_UNIQUE_ID, info);
    if (!result) {
        LOGD(AT_DOMAIN, AT_TAG, "Local device info not found for uuid %{public}s",
            ConstantCommon::EncryptDevId(uuid).c_str());
    } else {
        std::string dimUuid = info.deviceId.universallyUniqueId;
        if (uuid == dimUuid) {
            // refresh cache
            std::function<void()> fulfillDeviceInfo = [this]() {this->FulfillLocalDeviceInfo();};
            std::thread fulfill(fulfillDeviceInfo);
            fulfill.detach();
        }
    }

    return uuid;
}

std::string SoftBusManager::GetUniqueDeviceIdByNodeId(const std::string &networkId)
{
    if (!DataValidator::IsDeviceIdValid(networkId)) {
        LOGE(AT_DOMAIN, AT_TAG,
            "Invalid networkId: %{public}s", ConstantCommon::EncryptDevId(networkId).c_str());
        return "";
    }
    std::string udid;
    DistributedHardware::DeviceManager::GetInstance().GetUdidByNetworkId(TOKEN_SYNC_PACKAGE_NAME, networkId, udid);
    if (udid.empty()) {
        LOGE(AT_DOMAIN, AT_TAG, "Softbus return null or empty string: %{public}s",
            ConstantCommon::EncryptDevId(udid).c_str());
        return "";
    }
    std::string localUdid = ConstantCommon::GetLocalDeviceId();
    if (udid == localUdid) {
        // refresh cache
        std::function<void()> fulfillDeviceInfo = [this]() {this->FulfillLocalDeviceInfo();};
        std::thread fulfill(fulfillDeviceInfo);
        fulfill.detach();
    }
    return udid;
}

int SoftBusManager::FulfillLocalDeviceInfo()
{
    // repeated task will just skip
    if (!fulfillMutex_.try_lock()) {
        LOGI(AT_DOMAIN, AT_TAG, "FulfillLocalDeviceInfo already running, skip.");
        return Constant::SUCCESS;
    }

    DistributedHardware::DmDeviceInfo deviceInfo;
    int32_t res = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo(TOKEN_SYNC_PACKAGE_NAME,
        deviceInfo);
    if (res != Constant::SUCCESS) {
        LOGE(AT_DOMAIN, AT_TAG, "GetLocalDeviceInfo error");
        fulfillMutex_.unlock();
        return Constant::FAILURE;
    }
    std::string networkId = std::string(deviceInfo.networkId);

    LOGD(AT_DOMAIN, AT_TAG, "Call softbus finished, type:%{public}d", deviceInfo.deviceTypeId);

    std::string uuid;
    std::string udid;

    DistributedHardware::DeviceManager::GetInstance().GetUuidByNetworkId(TOKEN_SYNC_PACKAGE_NAME, networkId, uuid);
    DistributedHardware::DeviceManager::GetInstance().GetUdidByNetworkId(TOKEN_SYNC_PACKAGE_NAME, networkId, udid);
    if (uuid.empty() || udid.empty()) {
        LOGE(AT_DOMAIN, AT_TAG, "FulfillLocalDeviceInfo: uuid or udid is empty, abort.");
        fulfillMutex_.unlock();
        return Constant::FAILURE;
    }

    DeviceInfoManager::GetInstance().AddDeviceInfo(networkId, uuid, udid, std::string(deviceInfo.deviceName),
        std::to_string(deviceInfo.deviceTypeId));
    LOGD(AT_DOMAIN, AT_TAG, "AddDeviceInfo finished");

    fulfillMutex_.unlock();
    return Constant::SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

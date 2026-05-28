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

#ifndef ACCESS_TOKEN_HAP_SIGN_VERIFY_MANAGER_H
#define ACCESS_TOKEN_HAP_SIGN_VERIFY_MANAGER_H

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "access_token.h"
#include "app_verify_adapter.h"
#include "common/hap_byte_buffer.h"
#include "hap_data_structure.h"
#include "hap_token_info.h"
#include "interfaces/hap_verify.h"

namespace AppExecFwk {
namespace Spm {
struct InnerModuleInfoForSpm;
} // namespace Spm
} // namespace AppExecFwk

namespace Security {
namespace Verify {
struct ProvisionInfo;
struct BootstrapInfo;
} // namespace Verify
} // namespace Security

namespace OHOS {
namespace Security {
namespace AccessToken {

struct TrustedBundleInfoInner final {
public:
    std::string shareFilesRaw;
    std::shared_ptr<Security::Verify::BootstrapInfo> bootstrapInfo;
#ifdef X86_EMULATOR_MODE
    bool ignoreVerificationFailure = false;
#endif

    friend class MigrationVerifyHelper;
    friend class HapSignVerifyHelper;
    friend class HapSignVerifyManager;

    const std::string& GetModuleName() const;
    int32_t GetBundleType() const;
    int32_t GetApiTargetVersion() const;

    std::string GetBundleName() const;
    std::string GetAppIdentifier() const;
    std::string GetAppId() const;
    std::string GetApl() const;
    std::string GetAppDistributionType() const;
    std::string GetAppProvisionType() const;
    bool IsSystemApp() const;
    bool IsAtomicService() const;
    uint32_t GetSpmIdType() const;

private:
    AppExecFwk::Spm::InnerModuleInfoForSpm moduleData;
    Security::Verify::ProvisionInfo provisionInfo;
};

class HapSignVerifyManager final {
public:
    static HapSignVerifyManager& GetInstance();
    explicit HapSignVerifyManager(const IAppVerifyAdapter& adapter);

    int32_t CheckHapsSignInfo(const std::string path, const Security::Verify::VerifyType type, int32_t userId,
        TrustedBundleInfoInner& info, bool& isChanged) const;
    int32_t CheckMultipleHaps(const std::vector<TrustedBundleInfoInner>& infos) const;
    int32_t BuildHapPolicy(const std::vector<TrustedBundleInfoInner>& infos, HapPolicy& policy,
        BundleParam& param) const;
    int32_t CheckPermissionRequestValid(const TrustedBundleInfoInner& info, const HapPolicy& policy,
        HapInfoCheckResult& result) const;

private:
    HapSignVerifyManager();

    const IAppVerifyAdapter* adapter_;

    int32_t BuildTrustedBundleInfo(
        const std::shared_ptr<Security::Verify::BootstrapInfo>& bootstrapInfo,
        const Security::Verify::ProvisionInfo& provisionInfo, TrustedBundleInfoInner& info) const;
#ifdef X86_EMULATOR_MODE
    static TrustedBundleInfoInner BuildIgnoredTrustedBundleInfo();
#endif
};

class RdDeviceChecker final {
public:
    static bool IsRdDevice();

private:
    enum DeviceMode {
        NOT_INITIALIZE = 0,
        DEVICE_MODE_RD,
        DEVICE_MODE_NOT_RD
    };

    static constexpr int32_t CMDLINE_MAX_BUF_LEN = 4096;
    static constexpr const char* PROC_CMDLINE_FILE_PATH = "/proc/cmdline";

    static int32_t isRdDevice;
    static std::mutex rdDeviceMutex;

    static bool CheckDeviceMode(char *buf, ssize_t bufLen);
    static bool CheckEfuseStatus(char *buf, ssize_t bufLen);
    static void ParseCMDLine();
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_HAP_SIGN_VERIFY_MANAGER_H

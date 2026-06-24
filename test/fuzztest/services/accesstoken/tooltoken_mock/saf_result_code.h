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

#ifndef FUZZ_MOCK_SAF_RESULT_CODE_H
#define FUZZ_MOCK_SAF_RESULT_CODE_H

namespace OHOS {
namespace Security {
namespace SAF {
constexpr int32_t SAF_ERR_IPC_WRITE_DATA_FAIL = -30001;
constexpr int32_t SAF_ERR_IPC_READ_DATA_FAIL = -30002;
constexpr int32_t SAF_ERR_IPC_SEND_REQUEST_FAIL = -30003;
constexpr int32_t SAF_ERR_IPC_PROXY_FAIL = -30004;
constexpr int32_t SAF_ERR_IPC_ERROR = -30005;
constexpr int32_t SAF_ERR_IPC_INVALID_IPC_CODE = -30006;
constexpr int32_t SAF_ERR_SERVICE_UNAVAILABLE = -30007;
constexpr int32_t SAF_ERR_SERVICE_IS_STOPPING = -30008;
} // namespace SAF
} // namespace Security
} // namespace OHOS

#define SAF_ERR_IPC_WRITE_DATA_FAIL OHOS::Security::SAF::SAF_ERR_IPC_WRITE_DATA_FAIL
#define SAF_ERR_IPC_READ_DATA_FAIL OHOS::Security::SAF::SAF_ERR_IPC_READ_DATA_FAIL
#define SAF_ERR_IPC_SEND_REQUEST_FAIL OHOS::Security::SAF::SAF_ERR_IPC_SEND_REQUEST_FAIL
#define SAF_ERR_IPC_PROXY_FAIL OHOS::Security::SAF::SAF_ERR_IPC_PROXY_FAIL
#define SAF_ERR_IPC_ERROR OHOS::Security::SAF::SAF_ERR_IPC_ERROR
#define SAF_ERR_IPC_INVALID_IPC_CODE OHOS::Security::SAF::SAF_ERR_IPC_INVALID_IPC_CODE
#define SAF_ERR_SERVICE_UNAVAILABLE OHOS::Security::SAF::SAF_ERR_SERVICE_UNAVAILABLE
#define SAF_ERR_SERVICE_IS_STOPPING OHOS::Security::SAF::SAF_ERR_SERVICE_IS_STOPPING

#endif // FUZZ_MOCK_SAF_RESULT_CODE_H

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
#include <securec.h>
#include "socket.h"
#include "constant.h"
#include "soft_bus_manager.h"
#include "accesstoken_log.h"
#include "soft_bus_socket_listener.h"
#include "soft_bus_channel.h"

using namespace OHOS::Security::AccessToken;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "SoftBusSocketMock"};
static const int SERVER_COUNT_LIMIT = 10;
} // namespace

#define MIN_(x, y) ((x) < (y)) ? (x) : (y)

static int g_serverCount = -1;
bool IsServerCountOK()
{
    return g_serverCount >= 0 && g_serverCount < SERVER_COUNT_LIMIT;
}

static bool g_sendMessFlag = false;
int SendBytes(int sessionId, const void *data, unsigned int len)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "len: %{public}d", len);
    if (sessionId == Constant::INVALID_SESSION) {
        return Constant::FAILURE;
    }
    DecompressMock(reinterpret_cast<const unsigned char *>(data), len);
    g_sendMessFlag = true;
    return Constant::SUCCESS;
}

static std::string uuid = "";
void DecompressMock(const unsigned char *bytes, const int length)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "input length: %{public}d", length);
    uLong len = 1048576;
    unsigned char *buf = static_cast<unsigned char *>(malloc(len + 1));
    if (buf == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "no enough memory!");
        return;
    }
    (void)memset_s(buf, len + 1, 0, len + 1);
    int result = uncompress(buf, &len, const_cast<unsigned char *>(bytes), length);
    if (result != Z_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "uncompress failed, error code: %{public}d, bound length: %{public}d, buffer length: %{public}d", result,
            static_cast<int>(len), length);
        free(buf);
        return;
    }
    buf[len] = '\0';
    std::string str(reinterpret_cast<char *>(buf));
    free(buf);
    ACCESSTOKEN_LOG_DEBUG(LABEL, "done, output: %{public}s", str.c_str());

    std::size_t id_post = str.find("\"id\":");

    std::string id_string = str.substr(id_post + 6, 9);
    uuid = id_string;
    ACCESSTOKEN_LOG_DEBUG(LABEL, "id_string: %{public}s", id_string.c_str());
    return;
}


void CompressMock(const std::string &json, const unsigned char *compressedBytes, int &compressedLength)
{
    uLong len = compressBound(json.size());
    // length will not so that long
    if (compressedLength > 0 && (int) len > compressedLength) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "compress error. data length overflow, bound length: %{public}d, buffer length: %{public}d", (int) len,
            compressedLength);
        return ;
    }

    int result = compress(const_cast<Byte *>(compressedBytes), &len,
        reinterpret_cast<unsigned char *>(const_cast<char *>(json.c_str())), json.size() + 1);
    if (result != Z_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "compress failed! error code: %{public}d", result);
        return;
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "compress complete. compress %{public}d bytes to %{public}d", compressedLength,
        (int) len);
    compressedLength = len;
    return ;
}

std::string GetUuidMock()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetUuidMock called uuid: %{public}s", uuid.c_str());
    return uuid;
}

bool GetSendMessFlagMock()
{
    return g_sendMessFlag;
}

void ResetSendMessFlagMock()
{
    g_sendMessFlag = false;
}

void ResetUuidMock()
{
    uuid = "";
}

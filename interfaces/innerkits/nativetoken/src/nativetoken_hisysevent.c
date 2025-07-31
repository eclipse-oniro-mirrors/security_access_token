/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "nativetoken_hisysevent.h"

#include "accesstoken_klog.h"
#include "hisysevent_c.h"
#include "securec.h"

#define MSG_MAX_LEN 4096

void ReportNativeTokenExceptionEvent(int32_t sceneCode, int32_t errorCode, const char* errorMsg)
{
    if (errorMsg == NULL || strlen(errorMsg) == 0) {
        LOGC("Null or empty errorMsg.");
        return;
    }
    char tempErrorMsg[MSG_MAX_LEN + 1] = {0};
    if (strcpy_s(tempErrorMsg, sizeof(tempErrorMsg), errorMsg) != 0) {
        LOGC("Failed to copy error message.");
        return;
    }
    HiSysEventParam params[] = {
        {
            .name = "SCENE_CODE",
            .t = HISYSEVENT_INT32,
            .v = { .i32 = sceneCode },
            .arraySize = 0,
        },
        {
            .name = "ERROR_CODE",
            .t = HISYSEVENT_INT32,
            .v = { .i32 = errorCode },
            .arraySize = 0,
        },
        {
            .name = "ERROR_MSG",
            .t = HISYSEVENT_STRING,
            .v = { .s = tempErrorMsg },
            .arraySize = 0,
        },
    };
    OH_HiSysEvent_Write(ACCESS_TOKEND_DOMAIN, EVENT_NATIVE_TOKEN_EXCEPTION,
        HISYSEVENT_FAULT, params, sizeof(params) / sizeof(params[0]));
}

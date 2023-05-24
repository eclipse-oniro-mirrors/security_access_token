/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CODE_SIGNATURE_ANALYSIS_KIT_H
#define CODE_SIGNATURE_ANALYSIS_KIT_H

#include "analysis_model_log.h"
#include "code_signature_info.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CODE_SIGNATURE_ERROR_TYPE_SIZE 5

typedef void (*RetListener)(uint8_t *result, uint32_t resultLen);

typedef void (*DbListener)(uint32_t optType, uint8_t *result, uint32_t resultLen);

typedef struct ModelManagerApi {
    int32_t (*execSql)(const char *sql, uint8_t *result, uint32_t resultLen);
    int32_t (*subscribeDb)(const int64_t *eventId, uint32_t eventIdLen, DbListener listener);
} ModelManagerApi;

typedef struct ModelApi {
    int32_t (*init)(ModelManagerApi *api);
    int32_t (*getResult)(uint8_t *result, uint32_t *resultLen);
    int32_t (*subscribeResult)(RetListener listener);
    void (*release)();
} ModelApi;

/**
 * @brief Get the model.
 * @return A pointer to the model.
 */
ModelApi *GetModelApi(void);

/**
 * @brief Init the model.
 * @param api: The model api.
 * @return The event id nedd to be subscribed.
 */
int32_t Init(ModelManagerApi *api);

/**
 * @brief Release the model.
 * @return void.
 */
void Release(void);

/**
 * @brief Get the analysis result.
 * @param result: The analysis result info.
 * @return 0 indicates success, others indicate failure.
 */
int32_t GetResult(uint8_t *result, uint32_t *resultLen);

/**
 * @brief Subscribe the analysis result.
 * @param listener: The analysis result info.
 * @return 0 indicates success, others indicate failure.
 */
int32_t SubscribeResult(RetListener listener);

#ifdef __cplusplus
}
#endif

#endif // CODE_SIGNATURE_ANALYSIS_KIT_H

/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <stdint.h>
#include "cJSON.h"
#include "nativetoken.h"

#ifndef NATIVETOKEN_JSON_OPER_H
#define NATIVETOKEN_JSON_OPER_H

#ifdef __cplusplus
extern "C" {
#endif

extern void FreeStrArray(char **arr, int32_t num);
extern uint32_t GetProcessNameFromJson(cJSON *cjsonItem, NativeTokenList *tokenNode);
extern uint32_t GetTokenIdFromJson(cJSON *cjsonItem, NativeTokenList *tokenNode);
extern uint32_t GetAplFromJson(cJSON *cjsonItem, NativeTokenList *tokenNode);
extern uint32_t GetInfoArrFromJson(cJSON *cjsonItem, char *strArr[], int32_t *strNum, StrArrayAttr *attr);
extern cJSON *CreateNativeTokenJsonObject(const NativeTokenList *curr);
extern uint32_t UpdateGoalItemFromRecord(const NativeTokenList *tokenNode, cJSON *record);

#ifdef __cplusplus
}
#endif

#endif // NATIVETOKEN_JSON_OPER_H
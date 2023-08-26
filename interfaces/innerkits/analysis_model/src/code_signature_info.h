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

#ifndef CODE_SIGNATURE_INFO_H
#define CODE_SIGNATURE_INFO_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CODE_SIGNATURE_ERROR_TYPE_SIZE 5

#define APPLICATION_RISK_OF_CODE_SIGNATURE "code_signature"

#define APPLICATION_RISK_EVENT_ID 10110150100

#define CODE_SIGNATURE_ERROR_EVENT_ID 10110150101

#define INVALID_TOKEN_ID 0

#ifndef MAX_CODE_SIGNATURE_ERROR_NUM
#define MAX_CODE_SIGNATURE_ERROR_NUM 10
#endif

#ifndef MAX_CODE_SIGNATURE_ERROR_FREQUENCY
#define MAX_CODE_SIGNATURE_ERROR_FREQUENCY 10
#endif

#define MAX_BUNDLE_NAME_LENGTH 256
#define STATUS_CHANGED 1
#define STATUS_NOT_CHANGED 0

typedef enum  OperErrorCode {
    OPER_SUCCESS = 0,
    MEMORY_OPER_FAILED = 5501,
    INPUT_POINT_NULL = 5502,
    INPUT_TOKEN_ID_INVALID = 5503,
    INPUT_EVENT_TYPE_INVALID = 5504,
    INPUT_OPER_TYPE_INVALID = 5505,
    INIT_OPER_REPEAT = 5506,
    INVALID_POINT_LENGTH = 5507,
    MODEL_INIT_NOT_COMPLETED = 5508,
    SHORT_OF_MEMORY = 5509,
    RISK_APP_NUM_EXCEEDED = 5510,
} OperErrorCode;

typedef enum DataChangeTypeCode {
    EVENT_REPORTED = 0,
    OUT_OF_STORAGE_LIFE = 1,
    DATA_CHANGE_TYPE_BUFF,
} DataChangeTypeCode;

typedef enum CodeSignatureErrorType {
    SIGNATURE_MISSING = 0, // Signature is missing.
    SIGNATURE_INVALID, // Signature is invalid.
    ABC_FILE_TAMPERED, // abc file is tampered.
    BINARY_FILE_TAMPERED, // binary file is tampered.
    ELF_FORMAT_DAMAGED, // ELF of the file is damaged.
    CODE_SIGNATURE_ERROR_TYPE_BUFF,
} CodeSignatureErrorType;

typedef enum RiskPolicyType {
    NO_SECURITY_RISK = 0,
    LOG_REPORT,
    ENFORCED_PERMISSION_CONTROL,
    RISK_POLICY_TYPE_BUFF,
} RiskPolicyType;

typedef union TimeStampInfo {
    int64_t timeStampMs;
    int32_t timeStampCount;
} TimeStampInfo;

typedef struct TimeStampInfoNode {
    TimeStampInfo timeStamp;
    struct TimeStampInfoNode *next;
} TimeStampNode;

/* Code signature event infomation reported from security_guard */
typedef struct CodeSignatureReportedInfo {
    uint32_t tokenId;
    CodeSignatureErrorType errorType;
    int64_t timeStampMs;
    char bundleName[MAX_BUNDLE_NAME_LENGTH];
} CodeSignatureReportedInfo;

typedef struct CodeSignatureErrorInfo {
    CodeSignatureErrorType errorType;
    TimeStampNode *timeStampChain;
} CodeSignatureErrorInfo;

typedef struct AppRiskStatus {
    RiskPolicyType policy;
    int32_t eventCount;
    int64_t totalCount;
} AppRiskStatus;

typedef struct AppRiskInfo {
    uint32_t tokenId;
    AppRiskStatus status;
    char bundleName[MAX_BUNDLE_NAME_LENGTH];
    struct AppRiskInfo *next;
    CodeSignatureErrorInfo errInfoList[CODE_SIGNATURE_ERROR_TYPE_SIZE];
} AppRiskInfo;

typedef struct NotifyRiskResultInfo {
    int64_t eventId;
    RiskPolicyType policy;
    uint32_t tokenId;
} NotifyRiskResultInfo;

#ifdef __cplusplus
}
#endif

#endif // CODE_SIGNATURE_INFO_H

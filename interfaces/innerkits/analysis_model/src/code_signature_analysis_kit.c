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

#include "code_signature_analysis_kit.h"
#include <pthread.h>
#include <stdint.h>
#include <securec.h>

ModelManagerApi *g_securityGuardFunc = NULL;
ModelApi *g_modelFunc = NULL;
RetListener g_retListener = NULL;
AppRiskInfo *g_modelDataHead = NULL;
uint32_t g_riskAppCount = 0;
pthread_mutex_t g_modelVisitLock;
#define MAX_RISK_APP_COUNT (1024 * 100)

static AppRiskInfo *FindExistingNode(uint32_t tokenId)
{
    AppRiskInfo *node = g_modelDataHead->next;
    while (node != NULL) {
        if (node->tokenId == tokenId) {
            break;
        } else {
            node = node->next;
        }
    }
    return node;
}

static int32_t IsRiskStatusChanged(AppRiskInfo *node)
{
    int64_t totalCount = 0;
    int32_t eventCount = 0;
    RiskPolicyType policy = node->status.policy;

    for (int32_t i = 0; i < CODE_SIGNATURE_ERROR_TYPE_SIZE; i++) {
        TimeStampNode *tmp = ((node->errInfoList)[i]).timeStampChain;
        totalCount += tmp->timeStamp.timeStampCount;
        eventCount += (tmp->timeStamp.timeStampCount != 0) ? 1 : 0;
    }
    node->status.eventCount = eventCount;
    node->status.totalCount = totalCount;
    if ((totalCount > MAX_CODE_SIGNATURE_ERROR_NUM) || (eventCount == CODE_SIGNATURE_ERROR_TYPE_SIZE)) {
        node->status.policy = LOG_REPORT;
    } else {
        node->status.policy = NO_SECURITY_RISK;
    }

    int32_t isChanged = (node->status.policy != policy) ? STATUS_CHANGED : STATUS_NOT_CHANGED;
    if ((node->status.policy == NO_SECURITY_RISK) && (policy != NO_SECURITY_RISK)) {
        if (g_riskAppCount > 0) {
            g_riskAppCount--;
        }
        MODEL_LOG_INFO("[%s]:g_riskAppCount reduced.", __func__);
    } else if ((node->status.policy != NO_SECURITY_RISK) && (policy == NO_SECURITY_RISK)) {
        if (g_riskAppCount < MAX_RISK_APP_COUNT) {
            g_riskAppCount++;
        }
        MODEL_LOG_INFO("[%s]:g_riskAppCount added.", __func__);
    }
    return isChanged;
}

static int32_t DataPreProcess(const CodeSignatureReportedInfo *report,
                              AppRiskInfo *node,
                              uint32_t optType)
{
    TimeStampNode *head = ((node->errInfoList)[report->errorType]).timeStampChain;
    if (optType == OUT_OF_STORAGE_LIFE) {
        TimeStampNode *tmpNode = head->next;
        TimeStampNode *tmpNodePrev = head;
        while ((tmpNode != NULL) && (tmpNode->timeStamp.timeStampMs > report->timeStampMs)) {
            tmpNode = tmpNode->next;
            tmpNodePrev = tmpNodePrev->next;
        }
        tmpNodePrev->next = NULL;
        // Delete all the event timestamps which are out of storage life.
        while (tmpNode != NULL) {
            TimeStampNode *deleted = tmpNode;
            tmpNode = tmpNode->next;
            free(deleted);
            deleted = NULL;
            head->timeStamp.timeStampCount--;
        }
        return OPER_SUCCESS;
    }

    // Insert the newest report timestamp in the chain head.
    if (optType == EVENT_REPORTED) {
        TimeStampNode *tmp = NULL;
        tmp = (TimeStampNode *)malloc(sizeof(TimeStampNode));
        if (tmp == NULL) {
            MODEL_LOG_ERROR("[%s]:malloc failed.", __func__);
            return MEMORY_OPER_FAILED;
        }
        (void)memset_s(tmp, sizeof(TimeStampNode), 0, sizeof(TimeStampNode));
        tmp->timeStamp.timeStampMs = report->timeStampMs;
        tmp->next = head->next;
        head->next = tmp;
        head->timeStamp.timeStampCount++;
    }
    return OPER_SUCCESS;
}

static AppRiskInfo *AppRiskInfoNodeInit(void)
{
    AppRiskInfo *node = (AppRiskInfo *)malloc(sizeof(AppRiskInfo));
    if (node == NULL) {
        MODEL_LOG_ERROR("[%s]:malloc failed.", __func__);
        return NULL;
    }
    (void)memset_s(node, sizeof(AppRiskInfo), 0, sizeof(AppRiskInfo));

    TimeStampNode *tmp = NULL;
    tmp = (TimeStampNode *)malloc(sizeof(TimeStampNode) * CODE_SIGNATURE_ERROR_TYPE_SIZE);
    if (tmp == NULL) {
        MODEL_LOG_ERROR("[%s]:malloc failed.", __func__);
        free(node);
        return NULL;
    }
    (void)memset_s(tmp, sizeof(TimeStampNode) * CODE_SIGNATURE_ERROR_TYPE_SIZE,
                   0, sizeof(TimeStampNode) * CODE_SIGNATURE_ERROR_TYPE_SIZE);

    for (int32_t i = 0; i < CODE_SIGNATURE_ERROR_TYPE_SIZE; i++) {
        tmp[i].next = NULL;
        tmp[i].timeStamp.timeStampCount = 0;
        (node->errInfoList[i]).timeStampChain = &(tmp[i]);
    }
    node->status.eventCount = 0;
    node->status.totalCount = 0;
    node->status.policy = NO_SECURITY_RISK;
    node->next = g_modelDataHead->next;
    g_modelDataHead->next = node;
    return node;
}

static void ReleaseTimeStampChain(AppRiskInfo *node)
{
    for (int32_t i = 0; i < CODE_SIGNATURE_ERROR_TYPE_SIZE; i++) {
        TimeStampNode *head = (node->errInfoList[i]).timeStampChain->next;
        while (head != NULL) {
            TimeStampNode *tmp = head->next;
            free(head);
            head = tmp;
        }
    }
    // Free timeStampChain head for each error type. They was allocated together.
    free(node->errInfoList[0].timeStampChain);
    return;
}

static void SetResultInfoAccordingToNode(NotifyRiskResultInfo *result, AppRiskInfo *node)
{
    result->eventId = APPLICATION_RISK_EVENT_ID;
    result->tokenId = node->tokenId;
    result->policy = node->status.policy;
}

static int32_t UpdateInfoInCurrNode(const CodeSignatureReportedInfo *report, AppRiskInfo *node, uint32_t optType)
{
    int32_t res = DataPreProcess(report, node, optType);
    if (res != OPER_SUCCESS) {
        return res;
    }
    res = IsRiskStatusChanged(node);
    if (g_riskAppCount >= MAX_RISK_APP_COUNT) {
        return RISK_APP_NUM_EXCEEDED;
    }
    if (res == STATUS_NOT_CHANGED) {
        return OPER_SUCCESS;
    }
    if (g_retListener == NULL) {
        return OPER_SUCCESS;
    }
    /* Notify the SG db about APPLICATION_RISK_EVENT_ID change */
    NotifyRiskResultInfo *result = (NotifyRiskResultInfo *)malloc(sizeof(NotifyRiskResultInfo));
    if (result == NULL) {
        MODEL_LOG_ERROR("[%s]:malloc failed.", __func__);
        return MEMORY_OPER_FAILED;
    }
    (void)memset_s(result, sizeof(NotifyRiskResultInfo), 0, sizeof(NotifyRiskResultInfo));
    SetResultInfoAccordingToNode(result, node);

    // Notify the change.
    g_retListener((uint8_t *)result, sizeof(NotifyRiskResultInfo));
    free(result);
    return OPER_SUCCESS;
}

static int32_t AddNewAppInfoNode(const CodeSignatureReportedInfo *report, uint32_t optType)
{
    AppRiskInfo *node = AppRiskInfoNodeInit();
    if (node == NULL) {
        return MEMORY_OPER_FAILED;
    }

    node->tokenId = report->tokenId;
    int32_t res = strcpy_s(node->bundleName, MAX_BUNDLE_NAME_LENGTH - 1, report->bundleName);
    if (res != OPER_SUCCESS) {
        MODEL_LOG_ERROR("[%s]:strcpy_s failed errno %d.", __func__, errno);
        ReleaseTimeStampChain(node);
        free(node);
        return res;
    }

    res = DataPreProcess(report, node, optType);
    if (res != OPER_SUCCESS) {
        ReleaseTimeStampChain(node);
        free(node);
        return res;
    }

    (void)IsRiskStatusChanged(node);
    return OPER_SUCCESS;
}

static int32_t DataProcess(const CodeSignatureReportedInfo *report, uint32_t optType)
{
    if (report->tokenId == INVALID_TOKEN_ID) {
        MODEL_LOG_ERROR("[%s]:tokenId is invalid.", __func__);
        return INPUT_TOKEN_ID_INVALID;
    }
    if (report->errorType >= CODE_SIGNATURE_ERROR_TYPE_BUFF) {
        MODEL_LOG_ERROR("[%s]:errorType %d is invalid.", __func__, report->errorType);
        return INPUT_EVENT_TYPE_INVALID;
    }
    if (optType >= DATA_CHANGE_TYPE_BUFF) {
        MODEL_LOG_ERROR("[%s]:optType %u is invalid.", __func__, optType);
        return INPUT_OPER_TYPE_INVALID;
    }

    (void)pthread_mutex_lock(&g_modelVisitLock);
    if (g_modelDataHead == NULL) {
        MODEL_LOG_ERROR("[%s]:model is released.", __func__);
        (void)pthread_mutex_unlock(&g_modelVisitLock);
        return MODEL_INIT_NOT_COMPLETED;
    }
    AppRiskInfo *node = FindExistingNode(report->tokenId);
    if (node != NULL) {
        int32_t res = UpdateInfoInCurrNode(report, node, optType);
        (void)pthread_mutex_unlock(&g_modelVisitLock);
        return res;
    }

    // The deleted data is not in model cache already.
    if (optType == OUT_OF_STORAGE_LIFE) {
        (void)pthread_mutex_unlock(&g_modelVisitLock);
        return OPER_SUCCESS;
    }

    int32_t res = AddNewAppInfoNode(report, optType);
    (void)pthread_mutex_unlock(&g_modelVisitLock);

    return res;
}

static void DatabaseListener(uint32_t optType, uint8_t *result, uint32_t resultLen)
{
    if ((result == NULL) || (resultLen != sizeof(CodeSignatureReportedInfo))) {
        MODEL_LOG_ERROR("[%s]:ResultLen %u.", __func__, resultLen);
        return;
    }

    CodeSignatureReportedInfo *report = (CodeSignatureReportedInfo *)result;
    int32_t res = DataProcess(report, optType);
    if (res != OPER_SUCCESS) {
        MODEL_LOG_ERROR("[%s]:DataProcess failed. Res %d.", __func__, res);
    }
    return;
}

int32_t Init(ModelManagerApi *api)
{
    if (api == NULL) {
        MODEL_LOG_ERROR("[%s]:Input api func is null.", __func__);
        return INPUT_POINT_NULL;
    }

    (void)pthread_mutex_lock(&g_modelVisitLock);
    if (g_modelDataHead != NULL) {
        MODEL_LOG_ERROR("[%s]:Init has been completed already.", __func__);
        (void)pthread_mutex_unlock(&g_modelVisitLock);
        return INIT_OPER_REPEAT;
    }
    g_securityGuardFunc = api;

    g_modelDataHead = (AppRiskInfo *)malloc(sizeof(AppRiskInfo));
    if (g_modelDataHead == NULL) {
        MODEL_LOG_ERROR("[%s]:malloc failed.", __func__);
        (void)pthread_mutex_unlock(&g_modelVisitLock);
        return MEMORY_OPER_FAILED;
    }
    (void)memset_s(g_modelDataHead, sizeof(AppRiskInfo), 0, sizeof(AppRiskInfo));
    g_modelDataHead->next = NULL;

    // Set the func where to subscribe the db change.
    int64_t csErrEventId = CODE_SIGNATURE_ERROR_EVENT_ID;
    uint32_t eventIdLen = 1;
    g_securityGuardFunc->subscribeDb(&csErrEventId, eventIdLen, DatabaseListener);

    (void)pthread_mutex_unlock(&g_modelVisitLock);
    return OPER_SUCCESS;
}

void Release(void)
{
    (void)pthread_mutex_lock(&g_modelVisitLock);
    if (g_modelDataHead == NULL) {
        MODEL_LOG_ERROR("[%s]:Model has been release already.", __func__);
        (void)pthread_mutex_unlock(&g_modelVisitLock);
        return;
    }

    while (g_modelDataHead->next != NULL) {
        AppRiskInfo *node = g_modelDataHead->next;
        g_modelDataHead->next = node->next;
        ReleaseTimeStampChain(node);
        free(node);
    }
    free(g_modelDataHead);
    g_modelDataHead = NULL;
    g_retListener = NULL;
    g_securityGuardFunc = NULL;
    g_riskAppCount = 0;

    (void)pthread_mutex_unlock(&g_modelVisitLock);
    return;
}

int32_t GetResult(uint8_t *result, uint32_t *resultLen)
{
    if (result == NULL) {
        return INPUT_POINT_NULL;
    }

    (void)pthread_mutex_lock(&g_modelVisitLock);
    if (g_modelDataHead == NULL) {
        (void)pthread_mutex_unlock(&g_modelVisitLock);
        return MODEL_INIT_NOT_COMPLETED;
    }

    unsigned long long neededLen = g_riskAppCount * sizeof(NotifyRiskResultInfo);
    if (*resultLen < neededLen) {
        MODEL_LOG_ERROR("[%s]:ResultLen %u is smaller than needed %llu", __func__, *resultLen, neededLen);
        (void)pthread_mutex_unlock(&g_modelVisitLock);
        return SHORT_OF_MEMORY;
    }
    if (neededLen == 0) {
        *resultLen = 0;
        (void)pthread_mutex_unlock(&g_modelVisitLock);
        return OPER_SUCCESS;
    }

    NotifyRiskResultInfo *data = (NotifyRiskResultInfo *)malloc(neededLen);
    if (data == NULL) {
        (void)pthread_mutex_unlock(&g_modelVisitLock);
        return SHORT_OF_MEMORY;
    }
    AppRiskInfo *node = g_modelDataHead->next;
    uint32_t index = 0;
    while (node != NULL) {
        if (index == g_riskAppCount) {
            break;
        }
        if (node->status.policy > NO_SECURITY_RISK) {
            SetResultInfoAccordingToNode(&(data[index]), node);
            index++;
        }
        node = node->next;
    }
    int32_t ret = memcpy_s(result, *resultLen, data, sizeof(NotifyRiskResultInfo) * index);
    if (ret != OPER_SUCCESS) {
        MODEL_LOG_ERROR("[%s]:memcpy_s failed", __func__);
        *resultLen = 0;
    } else {
        *resultLen = sizeof(NotifyRiskResultInfo) * index;
    }
    free(data);
    data = NULL;
    (void)pthread_mutex_unlock(&g_modelVisitLock);
    return ret;
}

int32_t SubscribeResult(RetListener listener)
{
    if (listener == NULL) {
        MODEL_LOG_ERROR("[%s]:Listener is null", __func__);
        return INPUT_POINT_NULL;
    }

    (void)pthread_mutex_lock(&g_modelVisitLock);
    if (g_modelDataHead == NULL) {
        MODEL_LOG_ERROR("[%s]:Init is not completed yet", __func__);
        (void)pthread_mutex_unlock(&g_modelVisitLock);
        return MODEL_INIT_NOT_COMPLETED;
    }
    g_retListener = listener;
    (void)pthread_mutex_unlock(&g_modelVisitLock);
    return OPER_SUCCESS;
}

ModelApi *GetModelApi(void)
{
    int32_t res = pthread_mutex_init(&g_modelVisitLock, NULL);
    if (res != OPER_SUCCESS) {
        MODEL_LOG_ERROR("[%s]:pthread_mutex_init failed, res %d.", __func__, res);
        return NULL;
    }

    if (g_modelFunc != NULL) {
        return g_modelFunc;
    }
    g_modelFunc = (ModelApi *)malloc(sizeof(ModelApi));
    if (g_modelFunc == NULL) {
        MODEL_LOG_ERROR("[%s]: malloc failed", __func__);
        (void)pthread_mutex_destroy(&g_modelVisitLock);
        return g_modelFunc;
    }
    (void)memset_s(g_modelFunc, sizeof(ModelApi), 0, sizeof(ModelApi));
    g_modelFunc->init = Init;
    g_modelFunc->release = Release;
    g_modelFunc->getResult = GetResult;
    g_modelFunc->subscribeResult = SubscribeResult;

    return g_modelFunc;
}

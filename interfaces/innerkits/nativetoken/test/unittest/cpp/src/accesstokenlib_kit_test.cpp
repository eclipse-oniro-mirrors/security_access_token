/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "accesstokenlib_kit_test.h"

#include "accesstokenlib_kit.h"
#include "accesstoken_lib.h"

using namespace testing::ext;
using namespace OHOS::Security;

void TokenLibKitTest::SetUpTestCase()
{}

void TokenLibKitTest::TearDownTestCase()
{}

void TokenLibKitTest::SetUp()
{}

void TokenLibKitTest::TearDown()
{}

extern char *GetFileBuff(const char *cfg);

void * ThreadATMFuncBackUp(void *args)
{
    socklen_t len = sizeof(struct sockaddr_un);
    struct sockaddr_un addr;
    struct sockaddr_un clientAddr;
    int listenFd, ret;
    int readLen;

    /* set socket */
    (void)memset_s(&addr, sizeof(addr), 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (memcpy_s(addr.sun_path, sizeof(addr.sun_path), SOCKET_FILE, sizeof(addr.sun_path) - 1) != EOK) {
        return NULL;
    }
    unlink(SOCKET_FILE);
    listenFd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listenFd < 0) {
        ACCESSTOKEN_LOG_INFO("socket failed %d\n", listenFd);
        return NULL;
    }

    ::bind(listenFd, (struct sockaddr *)(&addr), (unsigned int)len);

    ret = listen(listenFd, 1);
    if (ret < 0) {
        ACCESSTOKEN_LOG_INFO("listenFd failed %d\n", errno);
        remove(SOCKET_FILE);
        close(listenFd);
        return NULL;
    }
    while (1) {
        int sockFd = accept(listenFd, (struct sockaddr *)(&clientAddr), &len);
        ACCESSTOKEN_LOG_INFO("accept sockFd %d\n", sockFd);
        do {
            readLen = read(sockFd, OHOS::Security::TokenLibKitTest::buffer, 102400);
            OHOS::Security::TokenLibKitTest::buffer[readLen] = '\0';
            ACCESSTOKEN_LOG_INFO("read :%s\n", OHOS::Security::TokenLibKitTest::buffer);
        } while (readLen > 0);

        close(sockFd);
        if (readLen < 0) {
            break;
        }
    }
    close(listenFd);
    return NULL;
}

int Start(const char *processName)
{
    const char *processname = processName;
    const char **dcaps = (const char **)malloc(sizeof(char *) * 2);
    dcaps[0] = "AT_CAP";
    dcaps[1] = "ST_CAP";
    int dcapNum = 2;
    pthread_t tid[2];
    (void)GetAccessTokenId(processname, dcaps, dcapNum, "system_core");

    if (strcmp("foundation", processname) == 0) {
        (void)pthread_create(&tid[0], 0, ThreadTransferFunc, NULL);
    }
    return 0;
}

HWTEST_F(TokenLibKitTest, TestAtlib, TestSize.Level1)
{
    pthread_t tid[2];

    AtlibInit();
    (void)pthread_create(&tid[1], 0, ThreadATMFuncBackUp, NULL);
    sleep(5);
    Start("process1");
    Start("process2");
    Start("process3");
    Start("process4");
    sleep(5);
    Start("foundation");
    Start("process5");
    Start("process6");
    sleep(20);
    Start("process7");
    Start("process8");
    Start("process9");
    sleep(50);

}

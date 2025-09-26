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
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "accesstoken_kit.h"
#include "privacy_kit.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
namespace {
static constexpr uint32_t INDEX_ZERO = 0;
static constexpr uint32_t INDEX_ONE = 1;
static constexpr uint32_t INDEX_TWO = 2;
static constexpr uint32_t INPUT_COUNT_ONE = 1;
static constexpr uint32_t INPUT_COUNT_TWO = 2;
static constexpr uint32_t INPUT_COUNT_THREE = 3;
static const std::string ACTION_HELP = "help";
static const std::string ACTION_SET = "set";
static const std::string ACTION_GET = "get";
static const std::string ACTION_REGISTER = "on";
static const std::string ACTION_UNREGISTER = "off";
static const std::string ACTION_LOOP = "loop";
static const std::string PERM_ALL = "all";
static const std::string PERM_CAMERA = "camera";
static const std::string PERM_MICRO = "micro";
static const std::string POLICY_TRUE = "true";
static const std::string POLICY_FALSE = "false";
static const std::string SET_HELP_INFO = "input: set camera/micro true/false\n";
static const std::string GET_HELP_INFO = "input: get camera/micro\n";
static const std::string REGISTER_HELP_INFO = "input: on all/camera/micro\n";
}

void ParseInput(const std::string& stringLine, std::vector<std::string>& inputs)
{
    std::istringstream iss(stringLine);
    std::string input;
    while (std::getline(iss, input, ' ')) {
        inputs.push_back(input);
    }
}

void PrintHelp()
{
    std::cout << "Usage:\n";
    std::cout << "  set camera/micro true/false\n";
    std::cout << "  get camera/micro\n";
    std::cout << "  on all/camera/micro\n";
    std::cout << "  off\n";
    std::cout << "  loop 1000\n";
    std::cout << "tips:\n";
    std::cout << "  off only can unregister last on.\n";
    std::cout << "  user can set loop count, such as loop 2000.\n";
    std::cout << "  press enter without any input to exit.\n" << std::endl;
}

AccessTokenID MockNativeToken(const std::string &process)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.processName = process;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    size_t pos = dumpInfo.find("\"tokenID\": ");
    if (pos == std::string::npos) {
        return 0;
    }
    pos += std::string("\"tokenID\": ").length();
    std::string numStr;
    while (pos < dumpInfo.length() && std::isdigit(dumpInfo[pos])) {
        numStr += dumpInfo[pos];
        ++pos;
    }

    std::istringstream iss(numStr);
    AccessTokenID tokenID;
    iss >> tokenID;
    return tokenID;
}

AccessTokenID g_edmTokenID = MockNativeToken("edm");
AccessTokenID g_atmTokenID = MockNativeToken("accesstoken_service");

void SetDisablePolicy(const std::string& permissionName, bool isDisable)
{
    SetSelfTokenID(g_edmTokenID);

    int32_t res = PrivacyKit::SetDisablePolicy(permissionName, isDisable);
    if (res != 0) {
        std::cout << "Set " << permissionName << " " << (isDisable ? "true " : "false ");
        std::cout << "failed, errCode is " << res << ".\n" << std::endl;
    } else {
        std::cout << "Set " << permissionName << " " << (isDisable ? "true " : "false ") << "success.\n" << std::endl;
    }
}

void AnalysisSetAndExcute(const std::vector<std::string>& inputs)
{
    if (inputs.size() < INPUT_COUNT_THREE) {
        std::cout << SET_HELP_INFO << std::endl;
        return;
    }

    std::string perm = inputs[INDEX_ONE];
    std::string permissionName;
    if (perm == PERM_CAMERA) {
        permissionName = "ohos.permission.CAMERA";
    } else if (perm == PERM_MICRO) {
        permissionName = "ohos.permission.MICROPHONE";
    } else {
        std::cout << SET_HELP_INFO << std::endl;
        return;
    }

    std::string policy = inputs[INDEX_TWO];
    bool isDisable = false;
    if (policy == POLICY_TRUE) {
        isDisable = true;
    } else if (policy == POLICY_FALSE) {
        isDisable = false;
    } else {
        std::cout << SET_HELP_INFO << std::endl;
        return;
    }
    
    SetDisablePolicy(permissionName, isDisable);
}

void GetDisablePolicy(const std::string& permissionName, bool& isDisable)
{
    SetSelfTokenID(g_atmTokenID);

    int32_t res = PrivacyKit::GetDisablePolicy(permissionName, isDisable);
    if (res != 0) {
        std::cout << "Get " << permissionName << " disable policy failed, errCode is " << res << ".\n" << std::endl;
    } else {
        std::cout << "Get " << permissionName << " disable policy success, result is ";
        std::cout << (isDisable ? "true" : "false") << ".\n" << std::endl;
    }
}

void AnalysisGetAndExcute(const std::vector<std::string>& inputs)
{
    if (inputs.size() < INPUT_COUNT_TWO) {
        std::cout << GET_HELP_INFO << std::endl;
        return;
    }

    std::string perm = inputs[INDEX_ONE];
    std::string permissionName;
    if (perm == PERM_CAMERA) {
        permissionName = "ohos.permission.CAMERA";
    } else if (perm == PERM_MICRO) {
        permissionName = "ohos.permission.MICROPHONE";
    } else {
        std::cout << GET_HELP_INFO << std::endl;
        return;
    }

    bool isDisable = false;
    GetDisablePolicy(permissionName, isDisable);
}

class DisablePolicyChangeCallbackTest : public DisablePolicyChangeCallback {
public:
    explicit DisablePolicyChangeCallbackTest(const std::vector<std::string> &permList)
        : DisablePolicyChangeCallback(permList) {}

    ~DisablePolicyChangeCallbackTest() {}

    virtual void PermDisablePolicyCallback(const PermDisablePolicyInfo& info)
    {
        permissionName = info.permissionName;
        isDisable = info.isDisable;

        std::cout << "Receive callback: " << permissionName << " set to ";
        std::cout << (isDisable ? "true" : "false") << ".\n" << std::endl;
    }

    std::string permissionName = "ohos.permission.INVALID";
    bool isDisable = false;
};

std::shared_ptr<DisablePolicyChangeCallbackTest> g_callback = nullptr;

void RegisterPermDisablePolicyCallback(const std::shared_ptr<DisablePolicyChangeCallbackTest>& callback)
{
    SetSelfTokenID(g_atmTokenID);

    int32_t res = PrivacyKit::RegisterPermDisablePolicyCallback(callback);
    if (res != 0) {
        std::cout << "Register disable policy change callback failed, errCode is " << res << ".\n" << std::endl;
    } else {
        std::cout << "Register disable policy change callback success!\n" << std::endl;
    }
}

void AnalysisRegisterAndExcute(const std::vector<std::string>& inputs)
{
    if (inputs.size() < INPUT_COUNT_TWO) {
        std::cout << REGISTER_HELP_INFO << std::endl;
        return;
    }

    std::string perm = inputs[INDEX_ONE];
    std::vector<std::string> permList;
    if (perm == PERM_CAMERA) {
        permList.emplace_back("ohos.permission.CAMERA");
    } else if (perm == PERM_MICRO) {
        permList.emplace_back("ohos.permission.MICROPHONE");
    } else if (perm != PERM_ALL) {
        std::cout << REGISTER_HELP_INFO << std::endl;
        return;
    }

    g_callback = std::make_shared<DisablePolicyChangeCallbackTest>(permList);
    RegisterPermDisablePolicyCallback(g_callback);
}

void UnRegisterPermDisablePolicyCallback(const std::shared_ptr<DisablePolicyChangeCallbackTest>& callback)
{
    SetSelfTokenID(g_atmTokenID);

    int32_t res = PrivacyKit::UnRegisterPermDisablePolicyCallback(callback);
    if (res != 0) {
        std::cout << "UnRegister disable policy change callback failed, errCode is " << res << ".\n" << std::endl;
    } else {
        std::cout << "UnRegister disable policy change callback success!\n" << std::endl;
    }
}

void AnalysisUnRegisterAndExcute(const std::vector<std::string>& inputs)
{
    if (inputs.size() < INPUT_COUNT_ONE) {
        std::cout << "input: off\n" << std::endl;
        return;
    }

    UnRegisterPermDisablePolicyCallback(g_callback);
}

void AnalysisLoopAndExcute(const std::vector<std::string>& inputs)
{
    if (inputs.size() < INPUT_COUNT_TWO) {
        std::cout << "input: loop 1000\n" << std::endl;
        return;
    }

    int32_t count = atoi(inputs[INDEX_ONE].c_str());
    std::vector<std::string> permList = { "ohos.permission.CAMERA" };
    auto callback = std::make_shared<DisablePolicyChangeCallbackTest>(permList);
    bool isDisable = false;

    for (int32_t i = 0; i < count; ++i) {
        RegisterPermDisablePolicyCallback(callback);
        SetDisablePolicy("ohos.permission.CAMERA", false);
        usleep(1000000); // 1000000us = 1s
        GetDisablePolicy("ohos.permission.CAMERA", isDisable);
        SetDisablePolicy("ohos.permission.CAMERA", true);
        usleep(1000000); // 1000000us = 1s
        GetDisablePolicy("ohos.permission.CAMERA", isDisable);
        UnRegisterPermDisablePolicyCallback(callback);
    }
}

void AnalysisInputsAndExcute(const std::vector<std::string>& inputs)
{
    std::string action = inputs[INDEX_ZERO];
    std::shared_ptr<DisablePolicyChangeCallbackTest> callback = nullptr;
    
    if (action == ACTION_HELP) {
        PrintHelp();
    } else if (action == ACTION_SET) {
        AnalysisSetAndExcute(inputs);
    } else if (action == ACTION_GET) {
        AnalysisGetAndExcute(inputs);
    } else if (action == ACTION_REGISTER) {
        AnalysisRegisterAndExcute(inputs);
    } else if (action == ACTION_UNREGISTER) {
        AnalysisUnRegisterAndExcute(inputs);
    } else if (action == ACTION_LOOP) {
        AnalysisLoopAndExcute(inputs);
    } else {
        PrintHelp();
    }
}

int32_t main(int argc, char *argv[])
{
    PrintHelp();

    std::string stringLine;
    std::vector<std::string> inputs;
    while (true) {
        getline(std::cin, stringLine);
        if (stringLine.empty()) {
            break;
        }

        ParseInput(stringLine, inputs);
        AnalysisInputsAndExcute(inputs);

        inputs.clear();
    }

    return 0;
}

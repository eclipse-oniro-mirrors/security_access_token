/*
 * Copyright (C) 2025-2026 Huawei Device Co., Ltd.
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
#ifndef SYSTEM_PARAMETERS_H
#define SYSTEM_PARAMETERS_H
#include <cstdint>
#include <limits>
#include <string>
#include <map>

namespace OHOS {
namespace system {
bool GetBoolParameter(const std::string& key, bool def);
void SetBoolParameter(const std::string& key, bool status);

// Int parameter state for tests. Header-inline on purpose: every test target
// that shadows the real "parameters.h" with this mock gets the state without
// a link-time dependency on parameters.cpp. Returns the stored value when
// the key was set via SetIntParameter, otherwise falls back to the default.
inline std::map<std::string, int32_t>& IntParameterState()
{
    static std::map<std::string, int32_t> state;
    return state;
}

inline int32_t GetStoredIntParameter(const std::string& key, int32_t def)
{
    auto& state = IntParameterState();
    auto iter = state.find(key);
    if (iter != state.end()) {
        return iter->second;
    }
    return def;
}

inline void SetIntParameter(const std::string& key, int32_t value)
{
    IntParameterState()[key] = value;
}

inline void ClearIntParameter(const std::string& key)
{
    IntParameterState().erase(key);
}

template<typename T>
T GetIntParameter(const std::string& key, T def, T min = std::numeric_limits<T>::min(),
    T max = std::numeric_limits<T>::max())
{
    (void)min;
    (void)max;
    return static_cast<T>(GetStoredIntParameter(key, static_cast<int32_t>(def)));
}
} // namespace OHOS::system
} // namespace OHOS

#endif // SYSTEM_PARAMETERS_H

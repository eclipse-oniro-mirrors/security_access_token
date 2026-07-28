# Frameworks Common

## 核心职责

包含 AccessToken 模块共享的工具、常量和 DFX 组件。关键组件：LOGC 日志、HiSysEvent 上报、数据验证、权限映射。

## LOGC 关键错误日志

### 核心原则

**仅对导致函数调用失败并提前返回的致命错误使用 `LOGC`**。禁止用于非阻塞错误、预期失败或高频数据报告。

### LOGC vs 其它日志宏

| 宏 | 级别 | HiSysEvent | 使用场景 |
| --- | --- | --- | --- |
| `LOGC` | ERROR | 是（FAULT） | 关键验证失败，触发故障追踪 |
| `LOGE` | ERROR | 否 | 一般错误 |
| `LOGW` | WARN | 否 | 警告 |
| `LOGI` | INFO | 否 | 信息 |
| `LOGD` | DEBUG | 否 | 调试 |

### 使用规则

1. **仅用于致命错误**：输入损坏、验证失败、不应出现的错误条件
2. **不用于**：
   - 预期的错误条件（如可选文件不存在）→ 用 `LOGE`
   - 统计收集或数据报告 → 禁止
   - 调试/跟踪信息 → 用 `LOGD`/`LOGI`
3. **违规处理**：必须清除缓存消息（`ClearThreadErrorMsg()`）

**理由**：`LOGC` 触发 HiSysEvent FAULT 上报，设计用于故障追踪。滥用会淹没故障跟踪系统。

### 工作机制

```cpp
#define LOGC(domain, tag, fmt, ...)            \
do { \
    HILOG_IMPL(LOG_CORE, LOG_ERROR, domain, tag, "[%{public}s]" fmt, __FUNCTION__, ##__VA_ARGS__); \
    AddEventMessage(domain, tag, "%" LOG_PUBLIC "s[%" LOG_PUBLIC "u]: " fmt, __func__, __LINE__, ##__VA_ARGS__); \
} while (0)
```

自动执行：
1. HiLog 记录（LOG_ERROR 级别）
2. 存储到线程本地存储
3. HiSysEvent 上报获取

### 使用示例

```cpp
bool DataValidator::IsBundleNameValid(const std::string& bundleName)
{
    bool ret = (!bundleName.empty() && (bundleName.length() <= MAX_LENGTH));
    if (!ret) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Bundle name %{public}s is invalid.", bundleName.c_str());
    }
    return ret;
}
```

## 线程本地错误消息

### API

```cpp
uint32_t GetThreadErrorMsgLen(void);   // 获取存储错误消息长度
const char* GetThreadErrorMsg(void);   // 获取存储的错误消息
void ClearThreadErrorMsg(void);        // 清除存储的错误消息
void AddEventMessage(...);             // 添加错误消息（LOGC 调用）
```

### 消息链

```cpp
// A() -> LOGC(...) -> "Error message A"
// B() -> A() -> LOGC(...) -> "Error message B <A[123]"
// 结果：线程本地存储 "Error message B <A[123]"
```

## HiSysEvent 上报

### 事件类型

| 事件名 | 类型 | 用途 |
| --- | --- | --- |
| `ACCESSTOKEN_EXCEPTION` | FAULT | LOGC 触发的关键错误 |
| `DATABASE_EXCEPTION` | FAULT | 数据库操作失败 |
| `ACCESSTOKEN_SERVICE_START` | STATISTIC | 服务启动统计 |
| `ACCESSTOKEN_SERVICE_START_ERROR` | FAULT | 服务启动失败 |
| `ADD_HAP` | STATISTIC | HAP token 创建 |
| `UPDATE_HAP` | STATISTIC | HAP token 更新 |
| `DEL_HAP` | STATISTIC | HAP token 删除 |

### ACCESSTOKEN_EXCEPTION 事件

LOGC 通过 `ReportSysCommonEventError()` 自动触发，上报后自动清除缓存消息。

### 域和标签

```cpp
#define ATM_DOMAIN  0xD005A01
#define ATM_TAG     "ATM"

#define PRI_DOMAIN  0xD005A02
#define PRI_TAG     "PRIVACY"
```

## 添加新故障追踪

```cpp
// 1. 在 hisysevent_common.h 定义场景代码
typedef enum AccessTokenExceptionSceneCode {
    FEATURE_CONFIG_PARSE_FAILED = 0x2000,
} AccessTokenExceptionSceneCode;

// 2. 在代码中使用 LOGC
bool ConfigPolicyLoader::LoadPermissionFeatureConfig()
{
    if (parseFailed) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Parse failed: %{public}s", filePath.c_str());
        return false;
    }
    return true;
}

// 3. 报告错误（如不在 IPC 路径）
if (GetThreadErrorMsgLen() > 0) {
    ReportSysCommonEventError(FEATURE_CONFIG_PARSE_FAILED, ERR_PARSE_FAILED);
}
```

## 推荐实践

1. **谨慎使用 LOGC**：仅用于关键验证失败
2. **清除错误消息**：HiSysEvent 上报后自动清除
3. **场景代码**：在 `hisysevent_common.h` 添加新故障点场景代码
4. **错误代码**：定义具体错误代码便于故障分析
5. **线程安全**：错误消息线程本地，支持多线程

# security_access_token<a name="ZH-CN_TOPIC_0000001101239136"></a>

-   [简介](#section11660541593)
-   [缩略词](#section161941989596)
-   [目录](#section119744591305)
-   [使用](#section137768191623)
    -   [接口说明](#section1551164914237)

-   [相关仓](#section1371113476307)

## 简介<a name="section11660541593"></a>

ATM是OpenHarmony上基于AccessToken构建的统一的应用权限管理能力。
应用的Accesstoken信息主要包括应用身份标识APPID、用户ID，应用分身索引、应用APL等级、应用权限信息等。每个应用的Accestoken信息由一个32bits的设备内唯一标识符TokenID来标识。
ATM模块主要提供如下功能：
-   提供基于TokenID的应用权限校验机制，应用访问敏感数据或者API时可以检查是否有对应的权限。
-   提供基于TokenID的Accestoken信息查询，应用可以根据tokenID查询自身的APL等级等信息。

## 缩略词<a name="section161941989596"></a>
-   AT:      AccessToken, 访问凭据
-   ATM:     AccessTokenManager, 访问凭据管理
-   API：    Application Programming Interface, 应用程序接口
-   APL:     API Ability Privilege Level, 元能力权限等级
-   APPID:   APP identity，应用身份标识
-   TokenID: Token identity，凭据身份标识

## 目录<a name="section161941989596"></a>

```
/base/security/access_token
├── frameworks                  # 框架层，基础功能代码存放目录
│   ├── accesstoken             # Accesstoken管理框架代码存放目录
│   ├── tokensync               # Accesstoken信息同步框架代码存放目录
│   └── common                  # 框架公共代码存放目录
├── interfaces                  # 接口层
│   └── innerkits               # 内部接口层
│       ├── accesstoken         # Accesstoken内部接口代码存放目录
│       └── tokensync           # Accesstoken信息同步内部接口代码存放目录
└── services                    # 服务层
    ├── accesstokenmanager      # Accesstoken管理服务代码存放目录
    └── tokensyncmanager        # Accesstoken信息同步服务代码存放目录
```

## 使用<a name="section137768191623"></a>
### 接口说明<a name="section1551164914237"></a>

| **接口申明** | **接口描述** |
| --- | --- |
| AccessTokenIDEx AllocHapToken(const HapInfoParams& info, const HapPolicyParams& policy); | 为应用进程分配一个tokenID |
| AccessTokenID AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID); | 为远端设备的应用进程分配一个本地tokenID |
| int UpdateHapToken(AccessTokenID tokenID, const std::string& appIDDesc, const HapPolicyParams& policy); | 更新tokenId对应的tokenInfo信息 |
| int DeleteToken(AccessTokenID tokenID); | 删除应用tokenID及其对应的tokenInfo信息 |
| int GetTokenType(AccessTokenID tokenID); | 查询指定tokenID的类型 |
| int CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap); | 检测指定tokenID对应的native进程是否具有指定的分布式能力 |
| AccessTokenID GetHapTokenID(int userID, const std::string& bundleName, int instIndex); | 查询指定应用的tokenId |
| int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes); | 查询指定tokenID对应的hap包的tokenInfo信息 |
| int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes); | 查询指定tokenID对应的native的tokenInfo信息 |
| int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName); | 检查指定tokenID是否具有指定权限 |
| int GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult); | 查询指定权限的权限定义信息 |
| int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList); | 查询指定tokenID对应的hap包的权限定义集合 |
| int GetReqPermissions(AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant); | 查询指定tokenID对应的hap包申请的权限状态集合 |
| int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName); | 查询指定tokenID的应用的指定权限 |
| int GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag); | 授予指定tokenID的应用的指定权限 |
| int RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag); | 撤销指定tokenID的应用的指定权限 |
| int ClearUserGrantedPermissionState(AccessTokenID tokenID); | 清空指定tokenID的应用的user_grant权限状态 |

## 相关仓<a name="section1371113476307"></a>
安全子系统

[startup\_init\_lite](https://gitee.com/openharmony/startup_init_lite/blob/master/README.md)

[security\_deviceauth](https://gitee.com/openharmony/security_deviceauth/blob/master/README.md)

**[security\_access\_token](https://gitee.com/openharmony-sig/security_access_token/blob/master/README.md)**
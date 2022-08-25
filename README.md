# Access Control<a name="EN-US_TOPIC_0000001101239136"></a>

 - [Introduction<a name="section11660541593"></a>](#introduction)
 - [Directory Structure<a name="section161941989596"></a>](#directory-structure)
 - [Usage<a name="section137768191623"></a>](#usage)
  - [Available APIs<a name="section1551164914237"></a>](#available-apis)
  - [Usage Guidelines<a name="section129654513264"></a>](#usage-guidelines)
   - [Native Process](#native-process)
   - [App HAP](#app-hap)
 - [Repositories Involved<a name="section1371113476307"></a>](#repositories-involved)

## Introduction<a name="section11660541593"></a>

AccessTokenManager (ATM) provides unified app permission management based on access tokens on OpenHarmony.

The access token information of an app includes the app identifier (**APPID**), user ID, app twin index, app Ability Privilege Level (APL), and permission information. The access token of each app is identified by a 32-bit token identity (**TokenID**) in the device.

The ATM module provides the following functions:
-   Verifying app permissions based on the token ID before an app accesses sensitive data or calls an API.
-   Obtaining access token information (for example, APL) based on the token ID.

## Directory Structure<a name="section161941989596"></a>

```
/base/security/access_token
├── frameworks                  # Stores code of basic functionalities.
│   ├── accesstoken             # Stores code of the ATM framework.
│   ├── tokensync               # Stores code of the access token synchronization framework.
│   └── common                  # Stores framework common code.
├── interfaces                  # Stores the APIs.
│   ├── innerkits               # Stores internal APIs.
│       ├── accesstoken         # Stores code of access token internal APIs.
│       ├── nativetoken         # Stores code of native token APIs.
│       └── tokensync           # Stores code of the internal APIs for access token synchronization.
└── services                    # Services
    ├── accesstokenmanager      # Stores ATM service code.
    └── tokensyncmanager        # Stores code of the access token synchronization service. 
```

## Usage<a name="section137768191623"></a>
### Available APIs<a name="section1551164914237"></a>

| **API**| **Description**|
| --- | --- |
| AccessTokenIDEx AllocHapToken(const HapInfoParams& info, const HapPolicyParams& policy); | Allocates a token ID to an app.|
| AccessTokenID AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID); | Allocates a local token ID to the app of a remote device.|
| int UpdateHapToken(AccessTokenID tokenID, const std::string& appIDDesc, int32_t apiVersion, const HapPolicyParams& policy); | Updates token information.|
| int DeleteToken(AccessTokenID tokenID); | Deletes the app's token ID and information.|
| int GetTokenType(AccessTokenID tokenID); | Obtains the type of an access token.|
| int CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap); | Checks whether the native process corresponding to the given token ID has the specified distributed capability.|
| AccessTokenID GetHapTokenID(int userID, const std::string& bundleName, int instIndex); | Obtains the token ID of an app.|
| int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes); | Obtains the token information about a HAP.|
| int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes); | Obtains information about a native token.|
| int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName); | Checks whether an access token has the specified permission.|
| int GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult); | Obtains definition information about the specified permission.|
| int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList); | Obtains the permission definition set of a HAP.|
| int GetReqPermissions(AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant); | Obtains the status set of the permission requested by a HAP.|
| int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName); | Obtains the permissions of the app with the specified token ID.|
| int GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag); | Grants the specified permission to the app with the specified token ID.|
| int RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag); | Revokes the specified permission from the app with the specified token ID.|
| int ClearUserGrantedPermissionState(AccessTokenID tokenID); | Clears the user_grant permission status of the app with the specified token ID.|
| uint64_t GetAccessTokenId(const char *processname, const char **dcap, int32_t dacpNum, const char *aplStr); | Obtains the token ID of a native process.|

### Usage Guidelines<a name="section129654513264"></a>
ATM provides unified access control for apps and allows apps or service abilities to obtain and verify app permissions and APL. The ATM APIs can be called by a service ability started by a native process or an app HAP.

#### Native Process
-  Before a native process starts, it calls **GetAccessTokenId** to obtain a token ID, and then calls **SetSelfTokenID** to set the token ID to the kernel.
-  During the running of a native process, it calls **GetNativeTokenInfo** or **CheckNativeDCap** to obtain the token information, including the distributed capability and APL.

#### App HAP
-  When an app is installed, **AllocHapToken** is called to obtain the token ID of the app.
-  When an authentication is required during app running, **VerifyAccessToken** or **GetReqPermissions** is called to obtain and verify the app permissions and APL.
-  When an app is uninstalled, **DeleteToken** is called to delete the related access token information.

## Repositories Involved<a name="section1371113476307"></a>

[startup\_init\_lite](https://gitee.com/openharmony/startup_init_lite/blob/master/README.md)

[security\_device\_auth](https://gitee.com/openharmony/security_device_auth/blob/master/README.md)

[security\_access\_token](https://gitee.com/openharmony/security_access_token/blob/master/README.md)

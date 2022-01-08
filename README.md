# security_access_token<a name="ZH-CN_TOPIC_0000001101239136"></a>

-   [简介](#section11660541593)
-   [缩略词](#section161941989596)
-   [目录](#section119744591305)
-   [使用](#section137768191623)
    -   [接口说明](#section1551164914237)
    -   [使用说明](#section129654513264)

-   [相关仓](#section1371113476307)

## 简介<a name="section11660541593"></a>

ATM是OpenHarmony上基于AccessToken构建的统一的应用权限管理能力。
应用的Accesstoken信息主要包括应用身份标识APPID、用户ID，应用分身索引、应用APL等级、应用权限信息等。每个应用的Accestoken信息由一个32bits的设备内唯一标识符tokenID来标识。
ATM模块主要提供如下功能：
-   提供基于tokenID的应用权限校验机制，应用访问敏感数据或者API时可以检查是否有对应的权限；
-   提供基于tokenID的Accestoken信息查询，应用可以根据tokenID查询自身的APL等级等信息；

## 缩略词<a name="section161941989596"></a>
-   AT:      AccessToken, 访问凭据
-   ATM:     AccessTokenManager, 访问凭据管理
-   API：    Application Programming Interface, 应用程序接口
-   APL:     API Ability Privilege Level, 权限访问控制列表
-   APPID:   APP identity，应用身份标识
-   tokenID: token identity，凭据身份标识

## 目录<a name="section161941989596"></a>

```
/base/security/access_token
├── frameworks                  # 框架层，基础功能代码存放目录，被interfaces和services使用
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

### 使用说明<a name="section129654513264"></a>
1.  xxxx
2.  xxxx
3.  xxxx

## 相关仓<a name="section1371113476307"></a>
安全子系统
[startup\_init\_lite](https://gitee.com/openharmony/startup_init_lite/blob/master/README.md)
[security\_deviceauth](https://gitee.com/openharmony/security_deviceauth/blob/master/README.md)
**[security\_access\_token](https://gitee.com/openharmony-sig/security_access_token/blob/master/README.md)**
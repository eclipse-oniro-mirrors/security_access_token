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

import { AsyncCallback, Callback, BusinessError } from '@ohos.base';
import { Permissions } from 'permissions';
import type _PermissionRequestResult from 'security.PermissionRequestResult';
import Context from 'application.Context';

function PARAM_ERROR_MSG(param: string, type: string): string {
    return `Parameter Error. The type of "${param}" must be ${type}.`;
}

export { Permissions };
export type PermissionRequestResult = _PermissionRequestResult;

class AsyncCallbackWrapper<T> {
  private wrapperCallback_: AsyncCallback<T, void> = (err: BusinessError<void> | null, data: T | undefined) => {}

  constructor(callback: AsyncCallback<T, void>) {
    this.wrapperCallback_ = callback;
  }

  invoke(err: BusinessError<void>, data: T) : void {
    this.wrapperCallback_(err, data);
  }
}

export default namespace abilityAccessCtrl {
    loadLibrary("accesstoken_ani.z");
    export enum GrantStatus {
        PERMISSION_DENIED = -1,
        PERMISSION_GRANTED = 0
    }

    export enum PermissionRequestToggleStatus {
        CLOSED = 0,
        OPEN = 1,
    }

    export enum PermissionStatus {
        DENIED = -1,
        GRANTED = 0,
        NOT_DETERMINED = 1,
        INVALID = 2,
        RESTRICTED = 3
    }

    interface PermissionStateChangeInfo {
        change: PermissionStateChangeType;
        tokenID: int;
        permissionName: Permissions;
    }

    export enum PermissionStateChangeType {
        PERMISSION_REVOKED_OPER = 0,
        PERMISSION_GRANTED_OPER = 1
    }

    export enum SwitchType {
        CAMERA = 0,
        MICROPHONE = 1,
        LOCATION = 2,
    }

    enum STSErrorCode {
        STS_OK = 0,
        STS_ERROR_PERMISSION_DENIED = 201,
        STS_ERROR_NOT_SYSTEM_APP = 202,
        STS_ERROR_PARAM_ILLEGAL = 401,
        STS_ERROR_SYSTEM_CAPABILITY_NOT_SUPPORT = 801,
    };

    class PermissionStateChangeInfoInner implements PermissionStateChangeInfo {
        change: PermissionStateChangeType;
        tokenID: int;
        permissionName: Permissions;
    }
    function validateRequestParams(context: Context, permissionList: Array<Permissions>): void {
        if ((typeof context === "undefined") || (context == null)) {
            let err = new BusinessError<string>();
            err.code = STSErrorCode.STS_ERROR_PARAM_ILLEGAL as int;
            err.data = PARAM_ERROR_MSG("context", "UIAbility or UIExtension Context");
            throw err;
        }
        if (typeof permissionList !== "object" || !Array.isArray(permissionList) ||
            permissionList.length == 0 || typeof permissionList[0] !== "string") {
            let err = new BusinessError<string>();
            err.code = STSErrorCode.STS_ERROR_PARAM_ILLEGAL as int;
            err.data = PARAM_ERROR_MSG("permissionList", "Array<Permissions>");
            throw err;
        }
    }

    native function createAtManager(): AtManager;
    interface AtManager {
        checkAccessTokenExecute(tokenID: int, permissionName: Permissions): int;
        requestPermissionsFromUserExecute(context: Context, permissionList: Array<Permissions>,
            callback: AsyncCallbackWrapper<PermissionRequestResult>): void;
        requestPermissionOnSettingExecute(context: Context,
            permissionList: Array<Permissions>, callback: AsyncCallbackWrapper<Array<GrantStatus>>): void;
        requestGlobalSwitchExecute(
            context: Context, type: int, callback: AsyncCallbackWrapper<boolean>): void;
        revokeUserGrantedPermissionExecute(tokenID: int, permissionName: Permissions, permissionFlags: int): void;
        getPermissionsStatusExecute(tokenID: int, permissionList: Array<Permissions>): Array<PermissionStatus>;
        getVersionExecute(): int;
        getPermissionFlagsExecute(tokenID: int, permissionName: Permissions): int;
        setPermissionRequestToggleStatusExecute(permissionName: Permissions, status: int): void;
        getPermissionRequestToggleStatusExecute(permissionName: Permissions): int;
        RequestAppPermOnSettingExecute(tokenID: int): undefined;
        onExcute(type: string, tokenIDList: Array<int>, permissionList: Array<Permissions>,
            callback: Callback<PermissionStateChangeInfo>): void;
        offExcute(type: string, tokenIDList: Array<int>, permissionList: Array<Permissions>,
            callback?: Callback<PermissionStateChangeInfo>): void;
        requestAppPermOnSettingExecute(tokenID: int): void;

        checkAccessTokenSync(tokenID: int, permissionName: Permissions): GrantStatus;
        verifyAccessTokenSync(tokenID: int, permissionName: Permissions): GrantStatus;
        checkAccessToken(tokenID: int, permissionName: Permissions): Promise<GrantStatus>;
        verifyAccessToken(tokenID: int, permissionName: Permissions): Promise<GrantStatus>;
        requestPermissionsFromUser(
            context: Context, permissionList: Array<Permissions>,
            requestCallback: AsyncCallback<PermissionRequestResult, void>): void;
        requestPermissionsFromUser(
            context: Context, permissionList: Array<Permissions>): Promise<PermissionRequestResult>;
        requestPermissionOnSetting(
            context: Context, permissionList: Array<Permissions>): Promise<Array<GrantStatus>>;
        requestGlobalSwitch(context: Context, type: SwitchType): Promise<boolean>;
        grantUserGrantedPermission(
            tokenID: int,
            permissionName: Permissions,
            permissionFlags: int,
            callback: AsyncCallback<void>): void;

        grantUserGrantedPermission(
            tokenID: int,
            permissionName: Permissions,
            permissionFlags: int): Promise<void>;

        revokeUserGrantedPermission(tokenID: int, permissionName: Permissions, permissionFlags: int): Promise<void>;
        revokeUserGrantedPermission(
            tokenID: int, permissionName: Permissions, permissionFlags: int, callback: AsyncCallback<void>): void;
        getVersion(): Promise<int>;
        getPermissionsStatus(tokenID: int, permissionList: Array<Permissions>): Promise<Array<PermissionStatus>>;
        getPermissionFlags(tokenID: int, permissionName: Permissions): Promise<int>;
        setPermissionRequestToggleStatus(
            permissionName: Permissions, status: PermissionRequestToggleStatus): Promise<void>;
        getPermissionRequestToggleStatus(permissionName: Permissions): Promise<PermissionRequestToggleStatus>;
        requestPermissionOnApplicationSetting(tokenID: int): Promise<void>;
        on(type: 'selfPermissionStateChange', permissionList: Array<Permissions>,
            callback: Callback<PermissionStateChangeInfo>): void;
        on(type: 'permissionStateChange', tokenIDList: Array<int>, permissionList: Array<Permissions>,
            callback: Callback<PermissionStateChangeInfo>): void;
        off(type: 'selfPermissionStateChange', permissionList: Array<Permissions>,
            callback?: Callback<PermissionStateChangeInfo>): void;
        off(type: 'permissionStateChange', tokenIDList: Array<int>, permissionList: Array<Permissions>,
            callback: Callback<PermissionStateChangeInfo>): void;
    }

    class AtManagerInner implements AtManager {
        native checkAccessTokenExecute(tokenID: int, permissionName: Permissions): int;
        native requestPermissionsFromUserExecute(context: Context, permissionList: Array<Permissions>,
            callback: AsyncCallbackWrapper<PermissionRequestResult>): void;
        native requestPermissionOnSettingExecute(context: Context,
            permissionList: Array<Permissions>, callback: AsyncCallbackWrapper<Array<GrantStatus>>): void;
        native requestGlobalSwitchExecute(
            context: Context, type: int, callback: AsyncCallbackWrapper<boolean>): void;
        native grantUserGrantedPermissionExecute(tokenID: int, permissionName: Permissions, permissionFlags: int): void;
        native revokeUserGrantedPermissionExecute(
            tokenID: int, permissionName: Permissions, permissionFlags: int): void;
        native getPermissionsStatusExecute(tokenID: int, permissionList: Array<Permissions>): Array<PermissionStatus>;
        native getVersionExecute(): int;
        native getPermissionFlagsExecute(tokenID: int, permissionName: Permissions): int;
        native setPermissionRequestToggleStatusExecute(permissionName: Permissions, status: int): void;
        native getPermissionRequestToggleStatusExecute(permissionName: Permissions): int;
        native RequestAppPermOnSettingExecute(tokenID: int): undefined;
        native onExcute(type: string, tokenIDList: Array<int>, permissionList: Array<Permissions>,
            callback: Callback<PermissionStateChangeInfo>): void;
        native offExcute(type: string, tokenIDList: Array<int>, permissionList: Array<Permissions>,
            callback?: Callback<PermissionStateChangeInfo>): void;
        native requestAppPermOnSettingExecute(tokenID: int): void;

        verifyAccessTokenSync(tokenID: int, permissionName: Permissions): GrantStatus {
            let result = this.checkAccessTokenExecute(tokenID, permissionName);
            return result as GrantStatus;
        }

        checkAccessTokenSync(tokenID: int, permissionName: Permissions): GrantStatus {
            let result = this.checkAccessTokenExecute(tokenID, permissionName);
            return result as GrantStatus;
        }

        checkAccessToken(tokenID: int, permissionName: Permissions): Promise<GrantStatus> {
            let p = new Promise<GrantStatus>((
                resolve: (v: GrantStatus) => void, reject: (error: BusinessError) => void) => {
                let p1 = taskpool.execute((): GrantStatus => {
                    return new AtManagerInner().checkAccessTokenExecute(tokenID, permissionName) as GrantStatus;
                });
                p1.then((e: NullishType) => {
                    resolve(e as GrantStatus);
                }).catch((err: Error): void => {
                    reject(err as BusinessError);
                });
            });
            return p;
        }

        verifyAccessToken(tokenID: int, permissionName: Permissions): Promise<GrantStatus> {
            let p = new Promise<GrantStatus>((
                resolve: (v: GrantStatus) => void, reject: (error: BusinessError) => void) => {
                let p1 = taskpool.execute((): GrantStatus => {
                    return new AtManagerInner().checkAccessTokenExecute(tokenID, permissionName) as GrantStatus;
                });
                p1.then((e: NullishType) => {
                    resolve(e as GrantStatus);
                }).catch((err: Error): void => {
                    resolve(GrantStatus.PERMISSION_DENIED);
                });
            });
            return p;
        }

        requestPermissionsFromUser(context: Context, permissionList: Array<Permissions>,
            requestCallback: AsyncCallback<PermissionRequestResult, void>): void {
            validateRequestParams(context, permissionList);
            let callbackWrap = new AsyncCallbackWrapper<PermissionRequestResult>(requestCallback);
            taskpool.execute((): void => {
                new AtManagerInner().requestPermissionsFromUserExecute(context, permissionList, callbackWrap);
            });
        }

        requestPermissionsFromUser(context: Context, permissionList: Array<Permissions>):
            Promise<PermissionRequestResult> {
            validateRequestParams(context, permissionList);
            let p: Promise<PermissionRequestResult> = new Promise<PermissionRequestResult>((
                resolve: (v: PermissionRequestResult) => void, reject: (error: BusinessError) => void) => {
                let callbackWrap = new AsyncCallbackWrapper<PermissionRequestResult>((
                    err: BusinessError<void> | null, data: PermissionRequestResult | undefined) => {
                    if (err?.code == 0) {
                        if (data !== undefined) {
                            resolve(data);
                        }
                    } else {
                        reject(err as BusinessError);
                    }
                });
                taskpool.execute((): void => {
                    new AtManagerInner().requestPermissionsFromUserExecute(context, permissionList, callbackWrap);
                });
            });
            return p;
        }

        requestPermissionOnSetting(context: Context, permissionList: Array<Permissions>): Promise<Array<GrantStatus>> {
            validateRequestParams(context, permissionList);
            let p: Promise<Array<GrantStatus>> = new Promise<Array<GrantStatus>>((
                resolve: (v: Array<GrantStatus>) => void, reject: (error: BusinessError) => void) => {
                let callbackWrap = new AsyncCallbackWrapper<Array<GrantStatus>>((
                    err: BusinessError<void> | null, data: Array<GrantStatus> | undefined) => {
                    if (err?.code == 0) {
                        if (data !== undefined) {
                            resolve(data);
                        }
                    } else {
                        reject(err as BusinessError);
                    }
                });
                taskpool.execute((): void => {
                    new AtManagerInner().requestPermissionOnSettingExecute(context, permissionList, callbackWrap);
                });
            });
            return p;
        }

        requestGlobalSwitch(context: Context, type: SwitchType): Promise<boolean> {
            if ((typeof context === "undefined") || (context == null)) {
                let err = new BusinessError<string>();
                err.code = STSErrorCode.STS_ERROR_PARAM_ILLEGAL;
                err.data = PARAM_ERROR_MSG("context", "UIAbility or UIExtension Context");
                throw err;
            }
            let p: Promise<boolean> = new Promise<boolean>((
                resolve: (v: boolean) => void, reject: (error: BusinessError) => void) => {
                let callbackWrap = new AsyncCallbackWrapper<boolean>((
                    err: BusinessError<void> | null, data: boolean | undefined) => {
                    if (err?.code == 0) {
                        if (data !== undefined) {
                            resolve(data);
                        }
                    } else {
                        reject(err as BusinessError);
                    }
                });
                taskpool.execute((): void => {
                    new AtManagerInner().requestGlobalSwitchExecute(context, type, callbackWrap);
                });
            });
            return p;
        }

        grantUserGrantedPermission(tokenID: int, permissionName: Permissions, permissionFlags: int,
            callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute((): void => {
                new AtManagerInner().grantUserGrantedPermissionExecute(tokenID, permissionName, permissionFlags);});
            p1.then(() => {
                callback(null, undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        grantUserGrantedPermission(tokenID: int, permissionName: Permissions, permissionFlags: int): Promise<void> {
            return new Promise<void>(
                (resolve: (v: undefined) => void, reject: (error: BusinessError) => void) : void => {
                let p = taskpool.execute(() : void => {
                    new AtManagerInner().grantUserGrantedPermissionExecute(tokenID, permissionName, permissionFlags);
                });
                p.then((e: NullishType) : void => {
                    resolve(undefined);
                }).catch((err: Error) : void => {
                    reject(err as BusinessError);
                });
            });
        }

        revokeUserGrantedPermission(tokenID: int, permissionName: Permissions, permissionFlags: int): Promise<void> {
            return new Promise<void>(
                (resolve: (v: undefined) => void, reject: (error: BusinessError) => void): void => {
                let p = taskpool.execute((): void => {
                    new AtManagerInner().revokeUserGrantedPermissionExecute(tokenID, permissionName, permissionFlags);
                });
                p.then((e: NullishType): void => {
                    resolve(undefined);
                }).catch((err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        revokeUserGrantedPermission(tokenID: int, permissionName: Permissions,
            permissionFlags: int, callback: AsyncCallback<void>): void {
            let job = taskpool.execute((): void => {
                new AtManagerInner().revokeUserGrantedPermissionExecute(tokenID, permissionName, permissionFlags);
            });
            job.then(() => {
                callback(null, undefined);
            }, (err: Error): void=> {
                callback(err as BusinessError, undefined);
            });
        }

        getVersion(): Promise<int> {
            let p = new Promise<int>((
                resolve: (v: int) => void, reject: (error: BusinessError) => void) => {
                    let p1 = taskpool.execute((): int => {
                        return new AtManagerInner().getVersionExecute() as int;
                    });
                    p1.then((e: NullishType) => {
                        resolve(e as int);
                    }).catch((err: Error): void => {
                        reject(err as BusinessError);
                    });
                });
            return p;
        }

        getPermissionsStatus(tokenID: int, permissionList: Array<Permissions>): Promise<Array<PermissionStatus>> {
            let p = new Promise<Array<PermissionStatus>>((
                resolve: (v: Array<PermissionStatus>) => void, reject: (error: BusinessError) => void) => {
                let p1 = taskpool.execute((): Array<PermissionStatus> => {
                    return new AtManagerInner().getPermissionsStatusExecute(
                        tokenID, permissionList) as Array<PermissionStatus>;
                });
                p1.then((e: NullishType) => {
                    resolve(e as Array<PermissionStatus>);
                }).catch((err: Error): void => {
                    reject(err as BusinessError);
                });
            });
            return p;
        }

        getPermissionFlags(tokenID: int, permissionName: Permissions): Promise<int> {
            let p = new Promise<int>(
                (resolve: (v: int) => void, reject: (err: BusinessError) => void): int => {
                let p1 = taskpool.execute((): int => {
                    return new AtManagerInner().getPermissionFlagsExecute(tokenID, permissionName);
                });
                p1.then((e: NullishType): void => {
                    resolve(e as int);
                }).catch((err: Error): void => {
                    reject(err as BusinessError);
                });
            })
            return p;
        }

        setPermissionRequestToggleStatus(permissionName: Permissions, status: PermissionRequestToggleStatus): Promise<void> {
            let p = new Promise<void>(
                (resolve: (v: undefined) => void, reject: (error: BusinessError) => void): void => {
                let p = taskpool.execute((): void => {
                    new AtManagerInner().setPermissionRequestToggleStatusExecute(permissionName, status);
                });
                p.then((e: NullishType): void => {
                    resolve(undefined);
                }).catch((err: Error): void => {
                    reject(err as BusinessError);
                });
            });
            return p;
        }

        getPermissionRequestToggleStatus(permissionName: Permissions): Promise<PermissionRequestToggleStatus> {
            let p =  new Promise<PermissionRequestToggleStatus>(
                (resolve: (v: PermissionRequestToggleStatus) => void,
                    reject: (err: BusinessError) => void): PermissionRequestToggleStatus => {
                    let p1 = taskpool.execute((): PermissionRequestToggleStatus => {
                        return new AtManagerInner().getPermissionRequestToggleStatusExecute(permissionName) as PermissionRequestToggleStatus;
                    });
                    p1.then((e: NullishType): void => {
                        resolve(e as PermissionRequestToggleStatus);
                    }).catch((err: Error): void => {
                        reject(err as BusinessError);
                    });
                });
            return p;
        }

        requestPermissionOnApplicationSetting(tokenID: int): Promise<void> {
            let p = new Promise<void>(
                (resolve: (v: undefined) => void, reject: (error: BusinessError) => void): void => {
                let p = taskpool.execute((): void => {
                    new AtManagerInner().requestAppPermOnSettingExecute(tokenID);
                });
                p.then((e: NullishType): void => {
                    resolve(undefined);
                }).catch((err: Error): void => {
                    reject(err as BusinessError);
                })
            });
            return p;
        }

        on(type: 'selfPermissionStateChange', permissionList: Array<Permissions>,
            callback: Callback<PermissionStateChangeInfo>): void {
                new AtManagerInner().onExcute('selfPermissionStateChange', [], permissionList, callback);
            }

        on(type: 'permissionStateChange', tokenIDList: Array<int>, permissionList: Array<Permissions>,
            callback: Callback<PermissionStateChangeInfo>): void {
                new AtManagerInner().onExcute('permissionStateChange', tokenIDList, permissionList, callback);
            }

        off(type: 'selfPermissionStateChange', permissionList: Array<Permissions>,
            callback?: Callback<PermissionStateChangeInfo>): void {
                new AtManagerInner().offExcute('selfPermissionStateChange', [], permissionList, callback);
            }

        off(type: 'permissionStateChange', tokenIDList: Array<int>, permissionList: Array<Permissions>,
            callback?: Callback<PermissionStateChangeInfo>): void {
                new AtManagerInner().offExcute('permissionStateChange', tokenIDList, permissionList, callback);
            }
    }
}

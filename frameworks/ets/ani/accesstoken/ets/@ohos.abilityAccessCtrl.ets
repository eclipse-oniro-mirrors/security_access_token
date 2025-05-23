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
import Context from 'application.Context'
import hilog from '@ohos.hilog';

function PARAM_ERROR_MSG(param: string, type: string): string {
    return `Parameter Error. The type of "${param}" must be ${type}.`;
}

export { Permissions };

export type PermissionRequestResult = _PermissionRequestResult;

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

    } ;
    function validateRequestParams(context: Context, permissionList: Array<Permissions>): void {
        if (typeof context === "undefined" || context == null) {
            let err = new BusinessError<string>();
            err.code = STSErrorCode.STS_ERROR_PARAM_ILLEGAL;
            err.data = PARAM_ERROR_MSG("context", "UIAbility or UIExtension Context");
            throw err;
        }
        if (typeof permissionList !== "object" || !Array.isArray(permissionList) || 
            permissionList.length == 0 || typeof permissionList[0] !== "string") {
            let err = new BusinessError<string>();
            err.code = STSErrorCode.STS_ERROR_PARAM_ILLEGAL;
            err.data = PARAM_ERROR_MSG("permissionList", "Array<Permissions>");
            throw err;
        }
    }

    function validateTokenAndPermission(tokenID: int, permissionName: Permissions): void {
        if (typeof permissionName !== "string") {
            let err = new BusinessError<string>();
            err.code = STSErrorCode.STS_ERROR_PARAM_ILLEGAL;
            err.data = PARAM_ERROR_MSG("permissionName", "Permissions");
            throw err;
        }
    }
    native function createAtManager(): AtManager;

    interface AtManager {
        checkAccessTokenANI(tokenID: int, permissionName: Permissions): int;
        checkAccessTokenSync(tokenID: int, permissionName: Permissions): GrantStatus;
        checkAccessToken(tokenID: int, permissionName: Permissions): Promise<GrantStatus>

        verifyAccessTokenSync(tokenID: int, permissionName: Permissions): GrantStatus;

        requestPermissionsFromUserExecute(
            context: Context,
            permissionList: Array<Permissions>):PermissionRequestResult;

        requestPermissionsFromUser(
            context: Context,
            permissionList: Array<Permissions>,
            requestCallback: AsyncCallback<PermissionRequestResult,void>
        ): void;

        requestPermissionsFromUser(
            context: Context,
            permissionList: Array<Permissions>): Promise<PermissionRequestResult>;

        requestPermissionOnSettingExecute(
            context: Context,
            permissionList: Array<Permissions>): Array<GrantStatus>;

        requestPermissionOnSetting(
            context: Context,
            permissionList: Array<Permissions>): Promise<Array<GrantStatus>>;
        
        revokeUserGrantedPermissionExecute(
            tokenID: int,
            permissionName: Permissions,
            permissionFlags: int,
        ): void;

        revokeUserGrantedPermission(
            tokenID: int,
            permissionName: Permissions,
            permissionFlags: int,
        ): Promise<void>;

        revokeUserGrantedPermission(
            tokenID: int,
            permissionName: Permissions,
            permissionFlags: int,
            callback: AsyncCallback<void>
        ): void;

        getVersionExecute(): int;

        getVersion(): Promise<int>;

        getPermissionsStatusExecute(
            tokenID: int, permissionList: Array<Permissions>): Array<PermissionStatus>;
            
        getPermissionsStatus(
            tokenID: int, permissionList: Array<Permissions>): Promise<Array<PermissionStatus>>;
    }

    class AtManagerInner implements AtManager {
        native checkAccessTokenANI(tokenID: int, permissionName: Permissions): int;

        verifyAccessTokenSync(tokenID: int, permissionName: Permissions): GrantStatus {
            validateTokenAndPermission(tokenID, permissionName);
            let result = this.checkAccessTokenANI(tokenID, permissionName);
            if (result == 0) {
                return GrantStatus.PERMISSION_GRANTED
            }
            return GrantStatus.PERMISSION_DENIED
        }

        checkAccessTokenSync(tokenID: int, permissionName: Permissions): GrantStatus {
            validateTokenAndPermission(tokenID, permissionName);
            let result = this.checkAccessTokenANI(tokenID, permissionName);
            if (result == 0) {
                return GrantStatus.PERMISSION_GRANTED
            }
            return GrantStatus.PERMISSION_DENIED
        }

        checkAccessToken(tokenID: int, permissionName: Permissions): Promise<GrantStatus> {
            validateTokenAndPermission(tokenID, permissionName);
            let p = new Promise<GrantStatus>((resolve: (v: GrantStatus)
                    => void, reject: (error: BusinessError) => void) => {
                let p1 = taskpool.execute((): GrantStatus => { return new AtManagerInner().checkAccessTokenANI(tokenID,
                    permissionName) as GrantStatus;});
                p1.then((e: NullishType) => {
                    resolve(e as GrantStatus);
                }).catch((err: BusinessError): void => {
                    reject(err);
                });
            });
            return p;
        }

        native requestPermissionsFromUserExecute(context: Context,
            permissionList: Array<Permissions>): PermissionRequestResult;

        requestPermissionsFromUser(context: Context, permissionList: Array<Permissions>,
            callback:AsyncCallback<PermissionRequestResult,void>): void {
            validateRequestParams(context, permissionList);
            let fun = async() => {
                try {
                    let work = new EAWorker();
                    let job = work.run<PermissionRequestResult>(() : PermissionRequestResult => {
                        return new AtManagerInner().requestPermissionsFromUserExecute(context, permissionList);
                    })
                    let result = job.Await();
                    let retError = new BusinessError<void>();
                    callback(retError, result as PermissionRequestResult);
                } catch (err: BusinessError) {
                    const defaultResult: PermissionRequestResult = {};
                    callback(err, defaultResult);
                }
            };
            fun();
        }

        requestPermissionsFromUser(context: Context, permissionList: Array<Permissions>):
            Promise<PermissionRequestResult> {
            validateRequestParams(context, permissionList);

            let p = new Promise<PermissionRequestResult>((resolve: (v: PermissionRequestResult) =>
                void, reject: (error: BusinessError) => void) => {
                let fun = async() => {
                    try {
                        let work = new EAWorker();
                        let job = work.run<PermissionRequestResult>((): PermissionRequestResult => {
                            return new AtManagerInner().requestPermissionsFromUserExecute(context, permissionList);
                        });
                        let result = job.Await();
                        resolve(result as PermissionRequestResult);
                    } catch (err: BusinessError) {
                        reject(err);
                    }
                };
                fun();
            });
            return p;
        }

        native requestPermissionOnSettingExecute(
            context: Context,
            permissionList: Array<Permissions>): Array<GrantStatus>;

        requestPermissionOnSetting(context: Context, permissionList: Array<Permissions>):
            Promise<Array<GrantStatus>> {
            validateRequestParams(context, permissionList);
            let p = new Promise<Array<GrantStatus>>((resolve: (v: Array<GrantStatus>) =>
                void, reject: (error: BusinessError) => void) => {
                let func = async() => {
                    try {
                        let work = new EAWorker();
                        let job = work.run<Array<GrantStatus>>((): Array<GrantStatus> => {
                            return new AtManagerInner().requestPermissionOnSettingExecute(context, permissionList);
                        });
                        let result = job.Await();
                        resolve(result as Array<GrantStatus>);
                    } catch (err: BusinessError) {
                        reject(err);
                    }
                };
                func();
            });
            return p;
        }
        
        native revokeUserGrantedPermissionExecute(tokenID: int, permissionName: Permissions,
            permissionFlags: int): void;

        revokeUserGrantedPermission(tokenID: int, permissionName: Permissions, permissionFlags: int): Promise<void> {
            return new Promise<void>(
                (resolve: (v: undefined) => void, reject: (error: BusinessError) => void): void => {
                let p = taskpool.execute((): void => {
                    new AtManagerInner().revokeUserGrantedPermissionExecute(tokenID, permissionName, permissionFlags);
                });
                p.then((e: NullishType): void => {
                    resolve(undefined);
                }).catch((err: BusinessError): void => {
                    reject(err);
                })
            });
        }

        revokeUserGrantedPermission(tokenID: int, permissionName: Permissions,
            permissionFlags: int, callback: AsyncCallback<void>): void {
            let job = taskpool.execute((): void => {
                new AtManagerInner().revokeUserGrantedPermissionExecute(tokenID, permissionName, permissionFlags);
            });
            job.then(()=>{
                let err = new BusinessError<void>();
                callback(err, undefined);
            }, (err: BusinessError): void=> {
                callback(err, undefined);
            })       
        }

        native getVersionExecute(): int;

        getVersion(): Promise<int>{
            let p = new Promise<int>((resolve: (v: int)=> void, reject: (error: BusinessError)
                => void) =>{
                    let p1 = taskpool.execute((): int => { return new AtManagerInner().getVersionExecute() as int;});
                    p1.then((e: NullishType) => {
                        resolve(e as int);
                    }).catch((err: BusinessError): void => {
                        reject(err);
                    });
                });
            return p;
        }

        native getPermissionsStatusExecute(
            tokenID: int, permissionList: Array<Permissions>): Array<PermissionStatus>;

        getPermissionsStatus(
            tokenID: int, permissionList: Array<Permissions>): Promise<Array<PermissionStatus>> {
            let p = new Promise<Array<PermissionStatus>>((resolve: (v: Array<PermissionStatus>)
                    => void, reject: (error: BusinessError) => void) => {
                let p1 = taskpool.execute((): Array<PermissionStatus> => { return new AtManagerInner().getPermissionsStatusExecute(tokenID,
                    permissionList) as Array<PermissionStatus>;});
                p1.then((e: NullishType) => {
                    resolve(e as Array<PermissionStatus>);
                }).catch((err: BusinessError): void => {
                    reject(err);
                });
            });
            return p;
        }
    }   
}
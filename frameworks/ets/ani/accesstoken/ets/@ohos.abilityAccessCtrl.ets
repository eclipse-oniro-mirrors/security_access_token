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

export const LOG_TAG = 0xC05A01;

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
    native function createAtManager(): AtManager;

    interface AtManager {
        checkAccessTokenANI(tokenID: int, permissionName: Permissions): int;
        checkAccessTokenSync(tokenID: int, permissionName: Permissions): GrantStatus;
        checkAccessToken(tokenID: int, permissionName: Permissions): Promise<GrantStatus>

        verifyAccessTokenSync(tokenID: int, permissionName: Permissions): GrantStatus;

        requestPermissionsFromUserExecute(
            context: Context,
            permissionList: Array<Permissions>): PermissionRequestResult;

        requestPermissionsFromUser(
            context: Context,
            permissionList: Array<Permissions>,
            requestCallback: AsyncCallback<PermissionRequestResult, void>
        ): void;
        
        requestPermissionsFromUser(
            context: Context,
            permissionList: Array<Permissions>): Promise<PermissionRequestResult>;
    }

    class AtManagerInner implements AtManager {
        native checkAccessTokenANI(tokenID: int, permissionName: Permissions): int;

        verifyAccessTokenSync(tokenID: int, permissionName: Permissions): GrantStatus {
            let result = this.checkAccessTokenANI(tokenID, permissionName);
            if (result == 0) {
                return GrantStatus.PERMISSION_GRANTED;
            }
            return GrantStatus.PERMISSION_DENIED;
        }

        checkAccessTokenSync(tokenID: int, permissionName: Permissions): GrantStatus {
            let result = this.checkAccessTokenANI(tokenID, permissionName);
            if (result == 0) {
                return GrantStatus.PERMISSION_GRANTED;
            }
            return GrantStatus.PERMISSION_DENIED;
        }

        checkAccessToken(tokenID: int, permissionName: Permissions): Promise<GrantStatus> {
            let p = new Promise<GrantStatus>((resolve: (v: GrantStatus)
                => void, reject: (error: BusinessError) => void) => {
                    let p1 = taskpool.execute((): GrantStatus => { return new AtManagerInner().checkAccessTokenANI(tokenID,
                        permissionName) as GrantStatus;});
                    p1.then((e: NullishType) => {
                        resolve(e as GrantStatus);
                    }).catch((err: Error): void => {
                        reject(err as BusinessError);
                    });
                });
            return p;
        }

        native requestPermissionsFromUserExecute(context: Context,
            permissionList: Array<Permissions>): PermissionRequestResult;

        requestPermissionsFromUser(context: Context, permissionList: Array<Permissions>,
            callback: AsyncCallback<PermissionRequestResult,void>): void {
            validateRequestParams(context, permissionList);
            let p2 = taskpool.execute((): PermissionRequestResult => {
                return new AtManagerInner().requestPermissionsFromUserExecute(context, permissionList)});
                p2.then((e: NullishType) => {
                    let retError = new BusinessError<void>();
                    callback(retError, e as PermissionRequestResult);
                }, (err: BusinessError): void=> {
                    if (err.code == STSErrorCode.STS_ERROR_PARAM_ILLEGAL) {
                        throw err;
                    }
                    callback(err, PermissionRequestResult);
                })
        }

        requestPermissionsFromUser(context: Context, permissionList: Array<Permissions>):
            Promise<PermissionRequestResult> {
            validateRequestParams(context, permissionList);
            let p = new Promise<PermissionRequestResult>((
                resolve: (v: PermissionRequestResult) => void, reject: (error: BusinessError) => void) => {
                let p1 = taskpool.execute((): PermissionRequestResult => {
                    return new AtManagerInner().requestPermissionsFromUserExecute(context, permissionList)});
                p1.then((e: NullishType)=> {
                    let r : PermissionRequestResult =  e as PermissionRequestResult;
                    resolve(r);
                }).catch((err: Error): void => {
                    if ((err as BusinessError).code == STSErrorCode.STS_ERROR_PARAM_ILLEGAL) {
                        throw err;
                    }
                    reject(err as BusinessError);
                });
            });
            return p;
        }
    }
}

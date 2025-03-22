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
    }

    class AtManagerInner implements AtManager {
        native checkAccessTokenANI(tokenID: int, permissionName: Permissions): int;
        checkAccessTokenSync(tokenID: int, permissionName: Permissions): GrantStatus{
            let result = this.checkAccessTokenANI(tokenID, permissionName);
            if (result == 0) {
                return GrantStatus.PERMISSION_GRANTED
            }
            return GrantStatus.PERMISSION_DENIED
        }
        checkAccessToken(tokenID: int, permissionName: Permissions): Promise<GrantStatus> {
            let p = new Promise<GrantStatus>((resolve: (v: GrantStatus) => void, reject: (error: Object) => void) => {
                let p1 = taskpool.execute((): int => { return new AtManagerInner().checkAccessTokenANI(tokenID,
                    permissionName)});
                p1.then((e: NullishType) => {
                    if(e == 0){
                        resolve(GrantStatus.PERMISSION_GRANTED);
                    }else{
                        resolve(GrantStatus.PERMISSION_DENIED);
                    }
                }, (err: Object): void => {
                });
            });
            return p;
        }

        verifyAccessTokenSync(tokenID: int, permissionName: Permissions): GrantStatus{
            let result = this.checkAccessTokenANI(tokenID, permissionName);
            if (result == 0) {
                return GrantStatus.PERMISSION_GRANTED
            }
            return GrantStatus.PERMISSION_DENIED
        }

        native requestPermissionsFromUserExecute(context: Context,
            permissionList: Array<Permissions>):PermissionRequestResult;

        requestPermissionsFromUser(
            context: Context,
            permissionList: Array<Permissions>,
            callback:AsyncCallback<PermissionRequestResult,void>):void{
            let p2 = taskpool.execute((): PermissionRequestResult => { 
                return new AtManagerInner().requestPermissionsFromUserExecute(context, permissionList)});
                p2.then((e: NullishType) => {
                    hilog.info(0xC05A01, 'requestPermissionsFromUser',`AsyncCallback success.`);
                    let retError = new BusinessError<void>();
                    retError.code = 0;
                    callback(retError, e as PermissionRequestResult)
                    },(err: Object): void => {
                        hilog.info(0xC05A01, 'requestPermissionsFromUser',`AsyncCallback failed.`);
                });
            }
        
        requestPermissionsFromUser(
            context: Context, 
            permissionList: Array<Permissions>): Promise<PermissionRequestResult>{
            let p = new Promise<PermissionRequestResult>((resolve: (v: PermissionRequestResult) => 
                void, reject: (error: Object) => void) => {
                    let p1 = taskpool.execute((): PermissionRequestResult => 
                    { let tmp = new AtManagerInner().requestPermissionsFromUserExecute(
                        context ,
                        permissionList) 
                        hilog.info(0xC05A01, 'requestPermissionsFromUser',
                        "requestPermissionsFromUser tmp");
                        return tmp;
                        });
                    p1.then((e :NullishType)=>{
                        hilog.info(0xC05A01, 'requestPermissionsFromUser',`Promise success.`);
                        let r : PermissionRequestResult =  e as PermissionRequestResult;
                        resolve(r);
                    }, (err: Object): void => {
                        hilog.info(0xC05A01, 'requestPermissionsFromUser',`Promise failed.`);
                });                           
            });
            return p;
        }
    }
}
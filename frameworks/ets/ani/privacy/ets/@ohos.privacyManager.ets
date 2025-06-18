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

import { AsyncCallback, Callback, BusinessError} from '@ohos.base';
import { Permissions } from 'permissions';
import hilog from '@ohos.hilog';

function PARAM_ERROR_MSG(param: string, type: string): string {
    return `Parameter Error. The type of "${param}" must be ${type}.`;
}

export { Permissions }

export default namespace privacyManager {
    hilog.info(0x0000, 'testTAG', '11111111111111111111111 privacyManager start');
    loadLibrary("privacy_ani.z");

    export interface AddPermissionUsedRecordOptions {
        usedType?: PermissionUsedType;
    }

    export native function addPermissionUsedRecordSExecute(
        tokenID: int, permissionName: Permissions, successCount: int, failCount: int,
        options: AddPermissionUsedRecordOptions): void;

    export native function startUsingPermissionExecute(
        tokenID: int, permissionName: Permissions, pid: int, usedType: int): void;
    export native function stopUsingPermissionExecute(tokenID: int, permissionName: Permissions, pid: int): void;
    export native function getPermissionUsedRecordExecute(request: PermissionUsedRequest): PermissionUsedResponse;
    export native function getPermissionUsedTypeInfosExecute(
        tokenId: int, permissionName: Permissions): Array<PermissionUsedTypeInfo>;
    export native function setPermissionUsedRecordToggleStatusExecute(status: boolean): void;
    export native function getPermissionUsedRecordToggleStatusExecute(): boolean;
    export native function onExecute(
        type: string, permissionList: Array<Permissions>, callback: Callback<ActiveChangeResponse>): void;
    export native function offExecute(
        type: string, permissionList: Array<Permissions>, callback?: Callback<ActiveChangeResponse>): void;

    export function addPermissionUsedRecord(tokenID: int, permissionName: Permissions, successCount: int,
        failCount: int, options?: AddPermissionUsedRecordOptions): Promise<void> {
        if (typeof permissionName !== "string") {
            let err = new BusinessError<string>();
            err.code = STSErrorCode.STS_ERROR_PARAM_ILLEGAL;
            err.data = PARAM_ERROR_MSG("permissionName", "Permissions");
            throw err;
        }
        hilog.info(0x0000, 'testTAG', '11111111111111111111111 addPermissionUsedRecord start');
        let usedTypeTemp : PermissionUsedType|undefined = options ? options.usedType : PermissionUsedType.NORMAL_TYPE;
        let optionsLocal: AddPermissionUsedRecordOptions = { usedType: usedTypeTemp };
        let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError) => void): void => {
            let p1 = taskpool.execute((): void => {
                privacyManager.addPermissionUsedRecordSExecute(
                    tokenID, permissionName, successCount, failCount, optionsLocal);
            });
            p1.then(() => {
                resolve(undefined);
            }).catch((err: Error): void => {
                reject(err as BusinessError);
            });
        });
        return p;
    }

    export function addPermissionUsedRecord(tokenID: int, permissionName: Permissions, successCount: int,
        failCount: int, callback: AsyncCallback<void>): void {
        if (typeof permissionName !== "string") {
            let err = new BusinessError<string>();
            err.code = STSErrorCode.STS_ERROR_PARAM_ILLEGAL;
            err.data = PARAM_ERROR_MSG("permissionName", "Permissions");
            throw err;
        }
        let options: AddPermissionUsedRecordOptions = { usedType: PermissionUsedType.NORMAL_TYPE };
        let p = taskpool.execute((): void => {
            privacyManager.addPermissionUsedRecordSExecute(tokenID, permissionName,
                successCount, failCount, options);
        });
        p.then(() => {
            let err = new BusinessError<void>();
            callback(err, undefined);
        },(err: Error): void=> {
            callback(err as BusinessError, undefined);
        });
    }

    export function stopUsingPermission(tokenID: int, permissionName: Permissions): Promise<void> {
        if (typeof permissionName !== "string") {
            let err = new BusinessError<string>();
            err.code = STSErrorCode.STS_ERROR_PARAM_ILLEGAL;
            err.data = PARAM_ERROR_MSG("permissionName", "Permissions");
            throw err;
        }
        let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError) => void): void => {
            let p1 = taskpool.execute((): void => {
                return privacyManager.stopUsingPermissionExecute(tokenID, permissionName, -1) });
            p1.then(() => {
                resolve(undefined);
            }).catch((err: Error): void => {
                reject(err as BusinessError);
            });
        });
        return p;
    }

    export function stopUsingPermission(tokenID: int, permissionName: Permissions, callback: AsyncCallback<void>): void {
        if (typeof permissionName !== "string") {
            let err = new BusinessError<string>();
            err.code = STSErrorCode.STS_ERROR_PARAM_ILLEGAL;
            err.data = PARAM_ERROR_MSG("permissionName", "Permissions");
            throw err;
        }
        let p = taskpool.execute((): void => {
            return privacyManager.stopUsingPermissionExecute(tokenID, permissionName, -1) });
        p.then(() => {
            let err = new BusinessError<void>();
            callback(err, undefined);
        },(err: Error): void=> {
            callback(err as BusinessError, undefined);
        });
    }

    export function stopUsingPermission(tokenID: int, permissionName: Permissions, pid?: int): Promise<void> {
        if (typeof permissionName !== "string") {
            let err = new BusinessError<string>();
            err.code = STSErrorCode.STS_ERROR_PARAM_ILLEGAL;
            err.data = PARAM_ERROR_MSG("permissionName", "Permissions");
            throw err;
        }
        let optionalPid: int = pid ?? -1;
        let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError) => void): void => {
            let p1 = taskpool.execute((): void => { 
                return privacyManager.stopUsingPermissionExecute(tokenID, permissionName, optionalPid) });
            p1.then(() => {
                resolve(undefined);
            }).catch((err: Error): void => {
                reject(err as BusinessError);
            });
        });
        return p;
    }

    export function startUsingPermission(tokenID: int, permissionName: Permissions): Promise<void> {
        if (typeof permissionName !== "string") {
            let err = new BusinessError<string>();
            err.code = STSErrorCode.STS_ERROR_PARAM_ILLEGAL;
            err.data = PARAM_ERROR_MSG("permissionName", "Permissions");
            throw err;
        }
        let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError) => void): void => {
            let p1 = taskpool.execute((): void => {
                return privacyManager.startUsingPermissionExecute(tokenID, permissionName,
                    -1, PermissionUsedType.NORMAL_TYPE) });
            p1.then(() => {
                resolve(undefined);
            }).catch((err: Error): void => {
                reject(err as BusinessError);
            });
        });
        return p;
    }

    export function startUsingPermission(tokenID: int, permissionName: Permissions, callback: AsyncCallback<void>): void {
        if (typeof permissionName !== "string") {
            let err = new BusinessError<string>();
            err.code = STSErrorCode.STS_ERROR_PARAM_ILLEGAL;
            err.data = PARAM_ERROR_MSG("permissionName", "Permissions");
            throw err;
        }
        let p = taskpool.execute((): void => {
            return privacyManager.startUsingPermissionExecute(tokenID, permissionName,
                -1, PermissionUsedType.NORMAL_TYPE) });
        p.then(() => {
            let err = new BusinessError<void>();
            callback(err, undefined);
        },(err: Error): void => {
            callback(err as BusinessError, undefined);
        })
    }

    export function startUsingPermission(tokenID: int, permissionName: Permissions, pid?: int,
        usedType?: PermissionUsedType): Promise<void> {
        if (typeof permissionName !== "string") {
            let err = new BusinessError<string>();
            err.code = STSErrorCode.STS_ERROR_PARAM_ILLEGAL;
            err.data = PARAM_ERROR_MSG("permissionName", "Permissions");
            throw err;
        }
        let optionalPid: int = pid ?? -1;
        let optionalUsedType = usedType ?? PermissionUsedType.NORMAL_TYPE;
        let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError) => void): void => {
            let p1 = taskpool.execute((): void => {
                return privacyManager.startUsingPermissionExecute(tokenID, permissionName,
                    optionalPid, optionalUsedType) });
            p1.then(() => {
                resolve(undefined);
            }).catch((err: Error): void => {
                reject(err as BusinessError);
            });
        });
        return p;
    }

    export function getPermissionUsedRecord(request: PermissionUsedRequest): Promise<PermissionUsedResponse> {
        return new Promise<PermissionUsedResponse>(
            (resolve: (data: PermissionUsedResponse) => void, reject: (error: BusinessError) => void): PermissionUsedResponse => {
            let p1 = taskpool.execute((): PermissionUsedResponse => {
                return privacyManager.getPermissionUsedRecordExecute(request);
            });
            p1.then((e: NullishType):void => {
                resolve(e as PermissionUsedResponse);
            }).catch((err: Error): void => {
                reject(err as BusinessError);
            });
        });
    }

    export function getPermissionUsedTypeInfos(tokenId?: int, permissionName?: Permissions): Promise<Array<PermissionUsedTypeInfo>>{
        let tokenIdIn = tokenId ? tokenId : 0;
        let permissionNameIn = permissionName ?? "";
        return new Promise<Array<PermissionUsedTypeInfo>>(
            (resolve: (v: Array<PermissionUsedTypeInfo>) => void, reject: (err:BusinessError) => void): Array<PermissionUsedTypeInfo> => {
            let p1 = taskpool.execute((): Array<PermissionUsedTypeInfo> => {
                return privacyManager.getPermissionUsedTypeInfosExecute(tokenIdIn, permissionNameIn);
            });
            p1.then((e: NullishType): void => {
                resolve(e as Array<PermissionUsedTypeInfo>);
            }).catch((err: Error): void => {
                reject(err as BusinessError);
            })
        });
    }

    export function setPermissionUsedRecordToggleStatus(status: boolean): Promise<void>{
        return new Promise<void>(
            (resolve: (v: undefined) => void, reject: (err: BusinessError) => void): void => {
            let p1 = taskpool.execute((): void => {
                privacyManager.setPermissionUsedRecordToggleStatusExecute(status);
            });
            p1.then((e: NullishType): void => {
                resolve(undefined);
            }).catch((err: Error): void => {
                reject(err as BusinessError);
            })
        });
    }

    export function getPermissionUsedRecordToggleStatus(): Promise<boolean>{
        return new Promise<boolean>(
            (resolve: (v: boolean) => void, reject: (err:BusinessError) => void): void => {
            let p1 = taskpool.execute((): boolean => {
                return privacyManager.getPermissionUsedRecordToggleStatusExecute();
            });
            p1.then((e: NullishType): void => {
                resolve(e as boolean);
            }).catch((err: Error): void =>{
                reject(err as BusinessError);
            })
        });     
    }

    export function on(
        type: string, permissionList: Array<Permissions>, callback: Callback<ActiveChangeResponse>): void {
        privacyManager.onExecute(type, permissionList, callback);
    }

    export function off(type: string, permissionList: Array<Permissions>, callback?: Callback<ActiveChangeResponse>): void {
        privacyManager.offExecute(type, permissionList, callback);
    }

        enum PermissionUsedType {
        NORMAL_TYPE = 0,
        PICKER_TYPE = 1,
        SECURITY_COMPONENT_TYPE = 2
    };

    enum PermissionActiveStatus {
        PERM_INACTIVE = 0,
        PERM_ACTIVE_IN_FOREGROUND = 1,
        PERM_ACTIVE_IN_BACKGROUND = 2
    };

    enum STSErrorCode {
        STS_OK = 0,
        STS_ERROR_PERMISSION_DENIED = 201,
        STS_ERROR_NOT_SYSTEM_APP = 202,
        STS_ERROR_PARAM_ILLEGAL = 401,
        STS_ERROR_SYSTEM_CAPABILITY_NOT_SUPPORT = 801,
    };

    enum PermissionUsageFlag {
        FLAG_PERMISSION_USAGE_SUMMARY = 0,
        FLAG_PERMISSION_USAGE_DETAIL = 1
    };

    interface PermissionUsedTypeInfo {
        tokenId: int;
        permissionName: Permissions;
        usedType: PermissionUsedType;
    }

    class PermissionUsedTypeInfoInner implements PermissionUsedTypeInfo {
        tokenId: int;
        permissionName: Permissions;
        usedType: PermissionUsedType;
    }

    interface ActiveChangeResponse {
        callingTokenId?: int;
        tokenId: int;
        permissionName: Permissions;
        deviceId: string;
        activeStatus: PermissionActiveStatus;
        usedType?: PermissionUsedType;
    }

    class ActiveChangeResponseInner implements ActiveChangeResponse {
        callingTokenId?: int;
        tokenId: int;
        permissionName: Permissions;
        deviceId: string;
        activeStatus: PermissionActiveStatus;
        usedType?: PermissionUsedType;
    }

    interface PermissionUsedRequest {
        tokenId: int;
        isRemote: boolean;
        deviceId: string;
        bundleName: string;
        permissionNames: Array<Permissions>;
        beginTime: long;
        endTime: long;
        flag: PermissionUsageFlag;
    }


    interface UsedRecordDetail {
        status: int;
        lockScreenStatus?: int;
        timestamp: long;
        count?: int;
        accessDuration: int;
        usedType?: PermissionUsedType;
    }

    class UsedRecordDetailInner implements UsedRecordDetail {
        status: int;
        lockScreenStatus?: int;
        timestamp: long;
        count?: int;
        accessDuration: int;
        usedType?: PermissionUsedType;
    }

    interface PermissionUsedRecord {
        permissionName: Permissions;
        accessCount: int;
        secAccessCount: int;
        rejectCount: int;
        lastAccessTime: long;
        lastRejectTime: long;
        lastAccessDuration: long;
        accessRecords: Array<UsedRecordDetail>;
        rejectRecords: Array<UsedRecordDetail>;
    }

    class PermissionUsedRecordInner implements PermissionUsedRecord{
        permissionName: Permissions;
        accessCount: int;
        secAccessCount: int;
        rejectCount: int;
        lastAccessTime: long;
        lastRejectTime: long;
        lastAccessDuration: long;
        accessRecords: Array<UsedRecordDetail>;
        rejectRecords: Array<UsedRecordDetail>;
    }

    interface BundleUsedRecord{
        tokenId: int;
        isRemote: boolean;
        deviceId: string;
        bundleName: string;
        permissionNames: Array<PermissionUsedRecord>;
    }

    class BundleUsedRecordInner implements BundleUsedRecord{
        tokenId: int;
        isRemote: boolean;
        deviceId: string;
        bundleName: string;
        permissionNames: Array<PermissionUsedRecord>;
    }

    interface PermissionUsedResponse {
        beginTime: long;
        endTime: long;
        bundleRecords: Array<BundleUsedRecord>;
    }

    class PermissionUsedResponseInner implements PermissionUsedResponse{
        beginTime: long;
        endTime: long;
        bundleRecords: Array<BundleUsedRecord>;
    }
}

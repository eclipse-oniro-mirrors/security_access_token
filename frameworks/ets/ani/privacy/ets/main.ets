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

import privacyManager from '@ohos.privacyManager';

function main(){
    console.println("hello ani")

    let options: privacyManager.AddPermissionUsedRecordOptions  = {
        usedType: privacyManager.PermissionUsedType.NORMAL_TYPE
    };

    let p = privacyManager.addPermissionUsedRecord(0, 'ohos.permission.READ_CONTACT', 1, 0)
    console.log("Start Invoked");
    p.then<void, void>((value: int): void => {
        console.log("Test passed. value : " + value);
    }, (err: Object): void => {
        console.log("Test failed. The promise shouldn`t be rejected.");
    });

    p = privacyManager.addPermissionUsedRecord(537093807, '', 1, 0,options)
    console.log("Start Invoked");
    p.then<void, void>((value: int): void => {
        console.log("Test passed. value : " + value);
    }, (err: Object): void => {
        console.log("Test failed. The promise shouldn`t be rejected.");
    });
    
    p = privacyManager.addPermissionUsedRecord(537000594, 'ohos.permission.READ_CONTACT', -1, 0,options)
    console.log("Start Invoked");
    p.then<void, void>((value: int): void => {
        console.log("Test passed. value : " + value);
    }, (err: Object): void => {
        console.log("Test failed. The promise shouldn`t be rejected.");
    });

    p = privacyManager.addPermissionUsedRecord(537093807, 'ohos.permission.test', 1, 0,options)
    console.log("Start Invoked");
    p.then<void, void>((value: int): void => {
        console.log("Test passed. value : " + value);
    }, (err: Object): void => {
        console.log("Test failed. The promise shouldn`t be rejected.");
    });

    p = privacyManager.addPermissionUsedRecord(672137215, 'ohos.permission.CAMERA', 1, 0,options)
    console.log("Start Invoked");
    p.then<void, void>((value: int): void => {
        console.log("Test passed. value : " + value);
    }, (err: Object): void => {
        console.log("Test failed. The promise shouldn`t be rejected.");
    });

    p = privacyManager.addPermissionUsedRecord(537093807, 'ohos.permission.CAMERA', 0, 0,options)
    console.log("Start Invoked");
    p.then<void, void>((value: int): void => {
        console.log("Test passed. value : " + value);
    }, (err: Object): void => {
        console.log("Test failed. The promise shouldn`t be rejected.");
    });

    
    let options2: privacyManager.AddPermissionUsedRecordOptions  = {
        usedType: privacyManager.PermissionUsedType.PICKER_TYPE
    };

    p = privacyManager.addPermissionUsedRecord(537000594, 'ohos.permission.CAMERA', 1, 0,options2)
    console.log("Start Invoked");
    p.then<void, void>((value: int): void => {
        console.log("Test passed. value : " + value);
    }, (err: Object): void => {
        console.log("Test failed. The promise shouldn`t be rejected.");
    });

    let options1: privacyManager.AddPermissionUsedRecordOptions  = {
        usedType: privacyManager.PermissionUsedType.SECURITY_COMPONENT_TYPE
    };

    p = privacyManager.addPermissionUsedRecord(672124712, 'ohos.permission.CAMERA', 1, 0,options1)
    console.log("Start Invoked");
    p.then<void, void>((value: int): void => {
        console.log("Test passed. value : " + value);
    }, (err: Object): void => {
        console.log("Test failed. The promise shouldn`t be rejected.");
    });

    p = privacyManager.addPermissionUsedRecord(672124712, 'ohos.permission.CAMERA', 1, 0)
    console.log("Start Invoked");
    p.then<void, void>((value: int): void => {
        console.log("Test passed. value : " + value);
    }, (err: Object): void => {
        console.log("Test failed. The promise shouldn`t be rejected.");
    });
}
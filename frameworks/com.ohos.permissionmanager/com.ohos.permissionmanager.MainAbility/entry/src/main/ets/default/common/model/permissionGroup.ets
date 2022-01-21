/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

export const permissionGroups: any[] = [
  { 'name': 'ohos.permission.READ_CALENDAR', "group": "CALENDAR"},
  { 'name': 'ohos.permission.WRITE_CALENDAR', "group": "CALENDAR"},
  { 'name': 'ohos.permission.READ_CALL_LOG', "group": "CALL_LOG"},
  { 'name': 'ohos.permission.WRITE_CALL_LOG', "group": "CALL_LOG"},
  { 'name': 'ohos.permission.READ_CONTACTS', "group": "CONTACTS"},
  { 'name': 'ohos.permission.WRITE_CONTACTS', "group": "CONTACTS"},
  { 'name': 'ohos.permission.ANSWER_CALL', "group": "PHONE"},
  { 'name': 'ohos.permission.MANAGE_VOICEMAIL', "group": "PHONE"},
  { 'name': 'ohos.permission.READ_CELL_MESSAGES', "group": "SMS"},
  { 'name': 'ohos.permission.READ_MESSAGES', "group": "SMS"},
  { 'name': 'ohos.permission.RECEIVE_MMS', "group": "SMS"},
  { 'name': 'ohos.permission.RECEIVE_SMS', "group": "SMS"},
  { 'name': 'ohos.permission.RECEIVE_WAP_MESSAGES', "group": "SMS"},
  { 'name': 'ohos.permission.SEND_MESSAGES', "group": "SMS"},
]

export const groups: any[] = [
  { 'name': 'CALENDAR',
    "permissions": ["ohos.permission.READ_CALENDAR", 'ohos.permission.WRITE_CALENDAR'],
    "groupName": '日历',
    "description": '访问日历和活动'
  },
  { 'name': 'CALL_LOG',
    "permissions": ["ohos.permission.READ_CALL_LOG", 'ohos.permission.WRITE_CALL_LOG'],
    "groupName": '通话记录',
    "description": '读取和写入手机通话记录'
  },
  { 'name': 'CONTACTS',
    "permissions": ["ohos.permission.READ_CONTACTS", 'ohos.permission.WRITE_CONTACTS'],
    "groupName": '通讯录',
    "description": '访问您的通讯录'
  },
  { 'name': 'PHONE',
    "permissions": ["ohos.permission.ANSWER_CALL", 'ohos.permission.MANAGE_VOICEMAIL'],
    "groupName": '电话',
    "description": '拨打电话和管理通话'
  },
  { 'name': 'SMS',
    "permissions": ["ohos.permission.READ_CELL_MESSAGES", 'ohos.permission.READ_MESSAGES', 'ohos.permission.RECEIVE_MMS', 'ohos.permission.RECEIVE_SMS', 'ohos.permission.RECEIVE_WAP_MESSAGES', 'ohos.permission.SEND_MESSAGES'],
    "groupName": '短信',
    "description": '发送和查看短信'
  },
]
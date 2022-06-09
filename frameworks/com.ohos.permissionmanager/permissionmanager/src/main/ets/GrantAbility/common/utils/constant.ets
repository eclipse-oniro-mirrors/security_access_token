/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

export default class Constants {
  // icon of dialog
  static DIALOG_ICON_WIDTH = 26;
  static DIALOG_ICON_HEIGHT = 24;
  static DIALOG_ICON_MARGIN_TOP = 23;

  // label text of dialog
  static DIALOG_LABEL_FONT_SIZE = 10;
  static DIALOG_LABEL_MARGIN_TOP = 2;
  static DIALOG_LABEL_LINE_HEIGHT = 14;

  // request text of dialog
  static DIALOG_REQ_FONT_SIZE = 16;
  static DIALOG_REQ_MARGIN_TOP = 16;
  static DIALOG_REQ_MARGIN_LEFT = 24;
  static DIALOG_REQ_LINE_HEIGHT = 22;

  // description text of dialog
  static DIALOG_DESP_FONT_SIZE = 14;
  static DIALOG_DESP_MARGIN_TOP = 2;
  static DIALOG_DESP_MARGIN_LEFT = 24;
  static DIALOG_DESP_MARGIN_RIGHT = 24;
  static DIALOG_DESP_MARGIN_BOTTOM = 8;
  static DIALOG_DESP_LINE_HEIGHT = 19;

  static BUTTON_FONT_SIZE = 16;
  static BUTTON_DIVIDER_FONT_SIZE = 24;
  static BUTTON_MARGIN_TOP = 8;
  static BUTTON_MARGIN_BOTTOM = 16;
  static BUTTON_MARGIN_LEFT = 16;
  static BUTTON_MARGIN_RIGHT = 16;
  static BUTTON_HEIGHT = 40;
  static BUTTON_WIDTH = 177;

  static DIALOG_BORDER_RADIUS = 32;
  static DIALOG_HEIGHT = 186;
  static DIALOG_WIDTH = 395;
  static DIALOG_PADDING_BOTTOM = 16;

  // initial check status
  static INIT_NEED_TO_WAIT = 0
  static INIT_NEED_TO_VERIFY = 1
  static INIT_NEED_TO_TERMINATED = 2

  static RESULT_SUCCESS = 1
  static RESULT_FAILURE = 0

  //
  static SETTING_OPER = -1
  static PASS_OPER = 0
  static DYNAMIC_OPER = 1
  static INVALID_OPER = 2

  //
  static PARMETER_BUNDLE_FLAG = 16
  static INITIAL_INDEX = 10

  static BUNDLE_NAME = 'com.ohos.permissionmanager'

  static START_SUBSCRIPT = 0
  static END_SUBSCRIPT = 500
}
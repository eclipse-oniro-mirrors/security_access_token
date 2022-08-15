/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
    // alphabetIndexer
    static ALPHABETINDEXER_SELECTEDFONT_SIZE = 12;
    static ALPHABETINDEXER_POPUPFONT_SIZE = 30;
    static ALPHABETINDEXER_ITEMSIZE = 16;
    static ALPHABETINDEXER_HEIGHT = 448;
    static ALPHABETINDEXER_WIDTH = 36;

    // backBar
    static BACKBAR_HEIGHT = 56;
    static BACKBAR_MINHEIGHT = 56;

    // image of backBar
    static BACKBAR_IMAGE_HEIGHT = 24;
    static BACKBAR_IMAGE_WIDTH = 24;
    static BACKBAR_IMAGE_MARGIN_TOP = 17;
    static BACKBAR_IMAGE_MARGIN_LEFT = 12;
    static BACKBAR_IMAGE_MARGIN_RIGHT = 15;

    // text of backBar
    static BACKBAR_TEXT_FONT_SIZE = 20;
    static BACKBAR_TEXT_FLEX_GROW = 1;
    static BACKBAR_TEXT_MARGIN_TOP = 17;

    // dialog
    static DIALOG_BORDER_RADIUS = 24;
    static DIALOG_HEIGHT = 70;
    static DIALOG_WIDTH = 336;

    // text of dialog
    static DIALOG_TEXT_FONT_SIZE = 20;
    static DIALOG_TEXT_MARGIN_TOP = 25;

    // search textInput
    static TEXTINPUT_PADDING_LEFT = 36;
    static TEXTINPUT_BORDER_RADIUS = 20;
    static TEXTINPUT_BORDER_WIDTH = 1.5;
    static TEXTINPUT_PLACEHOLDER_Font_SIZE = 16;
    static TEXTINPUT_HEIGHT = 40;
    static TEXTINPUT_IMAGE_WIDTH = 16;
    static TEXTINPUT_IMAGE_HEIGHT = 16;
    static TEXTINPUT_IMAGE_MARGIN_LEFT = 12;
    static TEXTINPUT_IMAGE_MARGIN_TOP = 12;

    // grid useSizeType
    static GRID_MARGIN = '0vp';
    static GUTTER = 0;
    static LEFT_XS_SPAN = 0;
    static LEFT_XS_OFFSET = 0;
    static LEFT_SM_SPAN = 0;
    static LEFT_SM_OFFSET = 0;
    static LEFT_MD_SPAN = 0;
    static LEFT_MD_OFFSET = 0;
    static LEFT_LG_SPAN = 2;
    static LEFT_LG_OFFSET = 0;
    static MIDDLE_XS_SPAN = 2;
    static MIDDLE_XS_OFFSET = 0;
    static MIDDLE_SM_SPAN = 4;
    static MIDDLE_SM_OFFSET = 0;
    static MIDDLE_MD_SPAN = 8;
    static MIDDLE_MD_OFFSET = 0;
    static MIDDLE_LG_SPAN = 8;
    static MIDDLE_LG_OFFSET = 2;
    static RIGHT_XS_SPAN = 0;
    static RIGHT_XS_OFFSET = 2;
    static RIGHT_SM_SPAN = 0;
    static RIGHT_SM_OFFSET = 4;
    static RIGHT_MD_SPAN = 0;
    static RIGHT_MD_OFFSET = 8;
    static RIGHT_LG_SPAN = 2;
    static RIGHT_LG_OFFSET = 10;

    // 100% width,height
    static FULL_WIDTH = '100%';
    static FULL_HEIGHT = '100%';

    // public property style
    static PERMISSION = 1;
    static APPLICATION = 0;
    static LAYOUT_WEIGHT = 1;
    static FLEX_GROW = 1;
    static TEXT_DECORATION_HEIGHT = 1;
    static TEXT_MIDDLE_FONT_SIZE = 16;
    static TEXT_SMAL_FONT_SIZE = 14;
    static TEXT_SMALLER_FONT_SIZE = 12;
    static TEXT_LINE_HEIGHT = 22;
    static TEXT_SMALL_LINE_HEIGHT = 19;
    static CONSTRAINTSIZE_MINHEIGHT = 48;
    static LISTITEM_ROW_HEIGHT = 48;
    static LISTITEM_PADDING_LEFT = 24;
    static LIST_PADDING_LEFT = 12
    static LISTITEM_PADDING_RIGHT = 24;
    static LISTITEM_PADDING_LEFT_RECORD = 32;
    static LISTITEM_MARGIN_BOTTOM = 12;
    static LISTITEM_MARGIN_BOTTOM_PERMISSION = 14;
    static LISTITEM_MARGIN_BOTTOM_APPLICATION = 10;
    static LISTITEM_HEIGHT_PERMISSION = 64;
    static LISTITEM_HEIGHT_APPLICATION = 72;
    static IMAGE_HEIGHT = 24;
    static IMAGE_WIDTH = 12;
    static IMAGE_HEIGHT_RECORD = 12;
    static IMAGE_WIDTH_RECORD = 24;
    static IMAGE_HEIGHT_RECORD_APPLICATION = 16;
    static IMAGE_WIDTH_RECORD_APPLICATION = 16;
    static BORDER_RADIUS = 24;
    static TITLE_MARGIN_BOTTOM = 16;
    static SUBTITLE_MIN_HEIGHT = 48;
    static SUBTITLE_LINE_HEIGHT = 24;
    static SUBTITLE_PADDING_TOP = 16;
    static SUBTITLE_PADDING_BOTTOM = 8;
    static TAB_HEIGHT = 56;
    static TAB_DECORATION_HEIGHT = 2;
    static TAB_DECORATION_POSITION_Y = 46;
    static DEFAULT_PADDING_START = 12;
    static DEFAULT_PADDING_END = 12;

    // application-secondary, authority-secondary
    static FLEX_MARGIN_TOP = 8;
    static FLEX_MARGIN_BOTTOM = 8;
    static LIST_PADDING_TOP = 4;
    static LIST_PADDING_BOTTOM = 4;
    static LIST_MARGIN_BOTTOM = 12;
    static ROW_MARGIN_TOP = 9;
    static SECONDARY_TEXT_MARGIN_TOP = 19.5;
    static SECONDARY_TEXT_MARGIN_LEFT = 24;
    static SECONDARY_LIST_PADDING_LEFT = 12;
    static SECONDARY_LIST_PADDING_RIGHT = 12;

    // application-tertiary
    static TERTIARY_IMAGE_WIDTH = 64;
    static TERTIARY_IMAGE_HEIGHT = 64;
    static TERTIARY_IMAGE_MARGIN_LEFT = 12;
    static TERTIARY_IMAGE_MARGIN_RIGHT = 12;
    static TERTIARY_LABEL_MARGIN_BOTTOM = 2;
    static TERTIARY_MARGIN_LEFT = 12;
    static TERTIARY_TEXT_MARGIN_LEFT = 24;
    static TERTIARY_HALF_WIDTH = '50%';
    static TERTIARY_ROW_MARGIN_TOP = 24;
    static TERTIARY_PERMISSION_ROW_MARGIN_TOP = 12;
    static TERTIARY_RADIO_IMAGE_WIDTH = 24;
    static TERTIARY_RADIO_IMAGE_HEIGHT = 24;
    static TERTIARY_RADIO_IMAGE_MARGIN_TOP = 4;
    static TERTIARY_LISTITEM_PADDING_LEFT = 24;
    static TERTIARY_LISTITEM_PADDING_RIGHT = 24;
    static TERTIARY_LISTITEM_MARGIN_TOP = 1;
    static TERTIARY_LIST_PADDING_LEFT = 12;
    static TERTIARY_LIST_PADDING_RIGHT = 12;
    static TERTIARY_LIST_PADDING_TOP = 4;
    static TERTIARY_LIST_PADDING_BOTTOM = 4;

    // authority-tertiary
    static AUTHORITY_IMAGE_WIDTH = 40;
    static AUTHORITY_IMAGE_HEIGHT = 40;
    static AUTHORITY_IMAGE_MARGIN_RIGHT = 16;
    static AUTHORITY_TOGGLE_WIDTH = 36;
    static AUTHORITY_TOGGLE_HEIGHT = 20;
    static AUTHORITY_ROW_HEIGHT = 72;
    static AUTHORITY_CONSTRAINTSIZE_MINHEIGHT = 72;
    static AUTHORITY_LISTITEM_PADDING_LEFT = 12;
    static AUTHORITY_LISTITEM_PADDING_RIGHT = 12;
    static AUTHORITY_TEXTINPUT_PADDING_LEFT = 12;
    static AUTHORITY_TEXTINPUT_PADDING_RIGHT = 24;
    static AUTHORITY_TEXT_MARGIN_TOP = 24;
    static AUTHORITY_TEXT_MARGIN_LEFT = 0;
    static AUTHORITY_ROW_MARGIN_TOP = 24;
    static NORECORD_IMAGE_WIDTH = 120;
    static NORECORD_IMAGE_HEIGHT = 120;
    static NORECORD_IMAGE_MARGIN_LEFT = 40;
    static SEARCHNORESULT_IMAGE_WIDTH = 200;
    static SEARCHNORESULT_IMAGE_HEIGHT = 200;
    static AUTHORITY_COLUMN_HEIGHT = '95%';
    static AUTHORITY_ALPHABETINDEX_WIDTH = 24;
    static AUTHORITY_ALPHABETINDEX_PADDING_TOP = 16;
    static AUTHORITY_TEXT_DECORATION_WIDTH = '86%';
    static AUTHORITY_TEXT_DECORATION_MARGIN_LEFT = 53;

    // authority-management
    static MANAGEMENT_IMAGE_WIDTH = 24;
    static MANAGEMENT_IMAGE_HEIGHT = 24;
    static MANAGEMENT_IMAGE_MARGIN_RIGHT = 16;
    static MANAGEMENT_IMAGE_MARGIN_RIGHT_RECORD = 24;
    static MANAGEMENT_IMAGE_MARGIN_LEFT = 8;
    static MANAGEMENT_ROW_HEIGHT = 56;
    static MANAGEMENT_TEXT_DECORATION_WIDTH = '95%';
    static MANAGEMENT_TEXT_DECORATION_MARGIN_LEFT = 40;
    static MANAGEMENT_LODING_IMAGE_WIDTH = 48;
    static MANAGEMENT_LODING_IMAGE_HEIGHT = 48;
    static MANAGEMENT_LODING_ROW_HEIGHT = '90%';
    static MANAGEMENT_ROW_PADDING_LEFT = 12;
    static MANAGEMENT_ROW_PADDING_RIGHT = 12;
    static MANAGEMENT_ROW_PADDING_TOP = 8;
    static MANAGEMENT_ROW_MARGIN_TOP = 12;
    static MANAGEMENT_TRANSPARENCY = 0.8;
    static APPLICATION_IMAGE_WIDTH = 40;
    static APPLICATION_IMAGE_HEIGHT = 40;
    static APPLICATION_IMAGE_MARGIN_RIGHT = 16;
    static APPLICATION_TEXT_MARGIN_RIGHT = 4;
    static APPLICATION_LIST_PADDING_LEFT = 12;
    static APPLICATION_LIST_PADDING_RIGHT = 12;
    static APPLICATION_LIST_MARGIN_BOTTOM = 50;
    static APPLICATION_LISTITEM_PADDING_LEFT = 12;
    static APPLICATION_LISTITEM_PADDING_RIGHT = 12;
    static APPLICATION_TEXTINPUT_PADDING_LEFT = 12;
    static APPLICATION_TEXTINPUT_PADDING_TOP = 8;
    static APPLICATION_TEXTINPUT_PADDING_RIGHT = 24;
    static APPLICATION_COLUMN_HEIGHT = '93%';
    static APPLICATION_ALPHABETINDEX_MARGIN_TOP = 12;
    static APPLICATION_ALPHABETINDEX_WIDTH = 24;
    static APPLICATION_TEXT_DECORATION_WIDTH = '90%';
    static APPLICATION_TEXT_DECORATION_MARGIN_LEFT = 56;
    static LOADING_WIDTH = 100;

    // slice
    static SLICE_START = 0;
    static SLICE_END = -1;
    static SLICE_START_INDEX = 0;
    static SLICE_END_INDEX = 1;

    //group number
    static FIXED_GROUP = 1;
    static CHANGE_GROUP = 2;
    static OTHER_GROUP = 3;

    // tabBar
    static BAR_WIDTH = 285;

    // setTimeout
    static DELAY_TIME = 1000;
    static DELAY_TIME_MAX = 2000;

    // radio
    static RADIO_ALLOW_NAME = '允许';
    static RADIO_ALLOW_INDEX = 0;
    static RADIO_ALLOW_GROUP_NAME = 'radio';
    static RADIO_BAN_NAME = '禁止';
    static RADIO_BAN_INDEX = 1;
    static RADIO_BAN_GROUP_NAME = 'radio';

    //shape
    static SHAPE_DIA = 24;
    static SHAPE_BAN_DIA = 23;
    static SHAPE_BIG_DIA = 48;
    static SHAPE_OFFSET_X = -24;
    static SHAPE_BAN_OFFSET = .5;
    static SHAPE_ALLOW_DIA = 16;
    static SHAPE_ALLOW_OFFSET = 4;
    static SHAPE_ZINDEX = 10;

    // utils
    static CHAR_CODE = 0;
    static UNI_MAX = 40869;
    static UNI_MIN = 19968;

    static PARMETER_BUNDLE_FLAG = 16;
    static USERID = 100;

    static PERMISSION_INDEX = 0;

    static PERMISSION_NUM = 0;

    static PERMISSION_FLAG = 2;
    static API_VERSION_SUPPORT_STAGE = 9;

    static PRE_AUTHORIZATION_NOT_MODIFIED = 4;

    static BUNDLE_NAME = 'com.ohos.permissionmanager'

    static START_SUBSCRIPT = 0
    static END_SUBSCRIPT = 500

    static RECORD_PADDING_BOTTOM = '20%'




    ////////////////////////////////////////////
    // icon of dialog
    static DIALOG_ICON_WIDTH = 24;
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

    static DIALOG_PRIVACY_BORDER_RADIUS = 32;
    static DIALOG_PRIVACY_WIDTH = 395;
    static DIALOG_PADDING_BOTTOM = 16;

    // initial check status
    static INIT_NEED_TO_WAIT = 0
    static INIT_NEED_TO_VERIFY = 1
    static INIT_NEED_TO_TERMINATED = 2
    static INIT_NEED_TO_REFRESH = 3

    static RESULT_SUCCESS = 1
    static RESULT_FAILURE = 0
    static RESULT_CODE = 0

    //
    static SETTING_OPER = -1
    static PASS_OPER = 0
    static DYNAMIC_OPER = 1
    static INVALID_OPER = 2

    //
    static INITIAL_INDEX = 10

}
package com.ohos.permissionmanager;

import ohos.ace.ability.AceAbility;
import ohos.aafwk.content.Intent;

public class MainAbility extends AceAbility {
    @Override
    public void onStart(Intent intent) {
        setInstanceName("main_ability");
        super.onStart(intent);
    }

    @Override
    public void onStop() {
        super.onStop();
    }
}

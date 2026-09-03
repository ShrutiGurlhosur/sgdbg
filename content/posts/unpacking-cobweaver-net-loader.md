---
title: "Unpacking CobWeaver: A .NET Loader With a Resource-Stuffed Stager"
date: 2026-08-15
draft: false
category: "malware-analysis"
tags: ["dotnet", "loader", "obfuscation", "yara"]
author: "Your Name"
summary: "Static and dynamic breakdown of a .NET loader delivered via a signed-looking installer, including its resource-decryption stager, C2 beacon format, and a YARA rule for detection."
tldr: "CobWeaver is a .NET loader that hides its second stage inside an encrypted PNG resource, decrypts it in memory with a rotating XOR key derived from the assembly's own GUID, and beacons over HTTPS with a JSON body disguised as telemetry."
iocs:
  - type: "SHA256"
    value: "3f2a9c1e6b7d4a8f0c5e9b2d1a7c6f4e8b3d0a9c2e5f1b7d4a6c8e0f2b9d3a17"
    note: "CobWeaver stager (Installer_v2.3.4.exe)"
  - type: "SHA256"
    value: "8e1d4c7a2f9b6e3d0c5a8f1b4e7d2a9c6f3b0e5d8a1c4f7b2e9d6a3c0f5b8e12"
    note: "Decrypted second-stage DLL"
  - type: "Domain"
    value: "cdn-metrics-sync[.]com"
    note: "C2 / beacon endpoint"
  - type: "URL"
    value: "hxxps://cdn-metrics-sync[.]com/api/v2/telemetry/sync"
    note: "Beacon check-in path"
  - type: "Mutex"
    value: "Global\\CW_9F3A2B1C"
    note: "Single-instance mutex on infected host"
---

> This is a sample writeup included to show the formatting this site uses for
> analysis reports — replace it with your own work. The sample below (family
> name, hashes, and domain) is illustrative, not a real threat.

## Overview

CobWeaver is a small .NET loader I came across attached to a fake "installer"
package for a cracked utility. The initial binary is unsigned but padded with
a resource section designed to look like assets for a legitimate installer
(icons, a PNG "splash screen", and a `.config` file). One of those resources
is not what it claims to be.

The chain is straightforward once unwound:

1. `Installer_v2.3.4.exe` — first-stage .NET loader, obfuscated with a
   commodity control-flow-flattening tool.
2. An embedded resource named `splash.png` — actually an XOR-encrypted PE,
   not an image.
3. A reflectively-loaded second-stage DLL that establishes persistence and
   beacons to a C2 over HTTPS.

## Static Analysis

### First-stage binary

The first-stage `.exe` is a 64-bit .NET assembly (`Any CPU`, .NET Framework
4.7.2 target). Key characteristics:

- No Authenticode signature.
- PE compile timestamp is zeroed out (`0x00000000`) — a common sign of a
  build pipeline that scrubs timestamps.
- String table is almost entirely encrypted; only framework-reference
  strings are visible in cleartext.
- Control flow is flattened with a switch-based dispatcher, consistent with
  a known open-source .NET obfuscator rather than a custom protector.

Extracting and decompiling with dnSpy shows an entry point that does very
little on its own — it immediately hands off to a class called
`Bootstrap.Init`, which does the actual work of locating and decrypting the
embedded resource.

### The resource isn't an image

```csharp
// simplified from decompiled output
var raw = Properties.Resources.splash; // byte[]
var key = Assembly.GetExecutingAssembly().ManifestModule.ModuleVersionId
                   .ToByteArray();      // per-build GUID used as XOR key
var stage2 = XorRotate(raw, key, skip: 0x2A); // skips fake PNG header
var asm = Assembly.Load(stage2);
asm.EntryPoint.Invoke(null, null);
```

The key detail: the XOR key isn't hardcoded, it's derived from the
assembly's own **Module Version ID** (a GUID Hugo... sorry, .NET assigns at
compile time). That means the key changes on every rebuild, which is likely
why static signature-based detections for this family tend to be short-lived
— each sample needs its own key derivation replayed to recover stage two,
which is exactly the kind of thing worth automating (see the
[extraction script](/scripts/) I published alongside this post once it's
in the section).

The first 0x2A bytes of `splash.png` are a real PNG header — enough to pass
a cursory file-type check by AV sandboxes that only peek at magic bytes —
before the encrypted payload begins.

### Second-stage DLL

Once decrypted, the second stage is a much smaller, purpose-built .NET DLL
(~40KB) with three responsibilities: persistence, beaconing, and command
execution.

Persistence is set via a scheduled task disguised as a Windows Update
maintenance task:

```
schtasks /create /tn "\Microsoft\Windows\WindowsUpdate\Sync" \
  /tr "regsvr32 /s /n /u /i:<path> scrobj.dll" /sc onlogon /rl highest
```

## Dynamic Analysis

Detonating the sample in an isolated sandbox produced the following
behavior:

- On first run, creates the mutex `Global\CW_9F3A2B1C` to avoid re-infecting
  the host.
- Drops the decrypted second stage to
  `%LOCALAPPDATA%\Microsoft\WindowsApps\wu_sync.dll` (not the real Windows
  Apps directory permissions, just borrowing the path for camouflage).
- Beacons over HTTPS to `cdn-metrics-sync[.]com` every 90–120 seconds
  (jittered) with a JSON body shaped like analytics telemetry:

```json
{
  "session_id": "a1b2c3d4",
  "event": "sync_complete",
  "metrics": { "duration_ms": 812, "cache_hit": true },
  "d": "BASE64_ENCODED_ENCRYPTED_BEACON_DATA"
}
```

The `d` field is where the actual C2 protocol lives — everything else in
the JSON body is decoration to blend in with benign analytics traffic on
casual inspection (and, presumably, with allow-listed egress rules that key
off JSON shape rather than destination).

Commands received in the response are simple: download-and-execute,
update-config, and uninstall (which removes the scheduled task and deletes
the dropped DLL — reasonably good self-cleanup for a loader this size).

## Detection

Because the XOR key is derived per-build, byte-signature rules on the
encrypted resource don't hold up well across samples. What does hold up:
the resource layout (fake PNG header length, encrypted payload following
it), the string used to name the mutex family, and the scheduled task
naming pattern. The YARA rule below targets the loader stub logic rather
than the encrypted blob:

**→ [CW_dotnet_loader_stub](/yara-rules/cw-dotnet-loader-stub/) YARA rule**

For network detection, the beacon's fixed JSON key set (`session_id`,
`event`, `metrics`, `d`) alongside a `d` value that is base64 but doesn't
decode to valid UTF-8 is a reasonable heuristic starting point for a
detection engineering rule, tuned against your own traffic baseline before
deploying.

## References

- Internal sandbox run notes, 2026-08-12.
- General background on .NET Module Version ID GUIDs and how they're
  assigned at compile time (Microsoft docs on `Module.ModuleVersionId`).

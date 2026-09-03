---
title: "CW_dotnet_loader_stub"
date: 2026-08-15
draft: false
family: "CobWeaver"
tags: ["dotnet", "loader"]
summary: "Detects the CobWeaver first-stage loader stub by its resource-decryption pattern and mutex-naming convention, independent of the per-build XOR key."
related_post: "/posts/unpacking-cobweaver-net-loader/"
---

Targets the loader stub described in
[Unpacking CobWeaver](/posts/unpacking-cobweaver-net-loader/). Because the
resource-decryption key is derived from each build's Module Version ID, this
rule avoids matching on the encrypted payload itself and instead keys on:

- the fake-PNG-header-then-encrypted-blob resource layout,
- the `Global\CW_` mutex naming convention, and
- the scheduled-task path used for persistence.

```yara
rule CW_dotnet_loader_stub
{
    meta:
        author      = "you"
        date        = "2026-08-15"
        description = "Detects CobWeaver .NET loader stub (stage 1)"
        reference   = "/posts/unpacking-cobweaver-net-loader/"
        family      = "CobWeaver"

    strings:
        // Resource named to masquerade as an image asset
        $res_name    = "splash.png" ascii wide

        // Mutex naming convention observed across samples
        $mutex       = "Global\\CW_" ascii wide

        // Persistence via disguised "Windows Update sync" scheduled task
        $sched_task  = "\\Microsoft\\Windows\\WindowsUpdate\\Sync" ascii wide
        $sched_cmd   = "regsvr32 /s /n /u /i:" ascii wide

        // .NET assembly marker + reflective load pattern
        $dotnet_hdr  = { 42 53 4A 42 }          // BSJB - .NET metadata magic
        $refl_load   = "Assembly.Load" ascii

    condition:
        uint16(0) == 0x5A4D                      // MZ header
        and $dotnet_hdr
        and $res_name
        and $refl_load
        and ( $mutex or ( $sched_task and $sched_cmd ) )
}
```

**False-positive notes:** the `Assembly.Load` + `splash.png` combination
alone is not unique enough to ship without the mutex or scheduled-task
strings — legitimate installers occasionally embed PNG resources and load
assemblies dynamically for plugin systems. Keep the condition's `and`
between the generic and specific strings intact.

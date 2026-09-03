---
title: "{{ replace .Name "-" " " | title }}"
date: {{ .Date }}
draft: true
family: ""
tags: []
summary: ""
related_post: ""
---

Short description of what this rule detects and why.

```yara
rule example_rule
{
    meta:
        author = "you"
        date = "{{ .Date }}"
        description = ""

    strings:
        $s1 = "example" ascii wide

    condition:
        uint16(0) == 0x5a4d and $s1
}
```

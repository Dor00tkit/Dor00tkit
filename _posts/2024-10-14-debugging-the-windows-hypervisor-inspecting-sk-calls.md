---
layout: post
title: "Debugging the Windows Hypervisor: Inspecting SK Calls"
date: "2024-10-14"
categories: 
  - "Hypervisors"
  - "Reverse-Engineering"
  - "Hyper-V"
  - "Windows-Internals"
tags: 
  - "Intel VT-x"
  - "Intel VMX"
  - "Intel Virtualization"
  - "Secure Kernel"
  - "Secure Calls"
  - "SSCN"
comments: false
---

## **Introduction & Motivation**
Recently, [Connor McGarr](https://x.com/33y0re) [tweeted](https://twitter.com/33y0re/status/1795967695722082601) about monitoring Secure System Calls while debugging the Windows kernel. I want to take it a step further and monitor the same SK calls while debugging the Windows hypervisor. Exploring Hyper-V's internals is my goal, as it promises an engaging research experience.  

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">Conditional breakpoint for monitoring Secure System Calls:<br>ba e1 /w &quot;@$curregisters.User.rdx == SECURE_SYSTEM_CALL_NUMBER&quot; nt!VslpEnterIumSecureMode<br><br>Useful for dynamic parameter inspection since the calls aren&#39;t really all that documented! <a href="https://t.co/4uSpw7HzL7">pic.twitter.com/4uSpw7HzL7</a></p>&mdash; Connor McGarr (@33y0re) <a href="https://twitter.com/33y0re/status/1795967695722082601?ref_src=twsrc%5Etfw">May 29, 2024</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## **Debugging Setup**
### **Guest**
For this blog post, I’ll be using [VMware Workstation 17 Professional](https://blogs.vmware.com/workstation/2024/05/vmware-workstation-pro-now-available-free-for-personal-use.html) (which now is free!) and I’ll be running `Windows 11 Pro Version 23H2 (OS Build 22631.2861)` as my guest.  
First, ensure that the option `Virtualize Intel VT-x/EPT or AMD-V/RVI` under the `Processors` settings is enabled.  
Next, within the VM we are going to [enable Virtualization-based security](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity) (VBS) and [memory integrity](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity#use-registry-keys-to-enable-memory-integrity).  
The last step for the guest VM is to configure the settings for [hypervisor debugging](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--hypervisorsettings), open CMD as administrator, and type:  

> bcdedit /hypervisorsettings net hostip:192.168.100.1 port:50001 key:a.b.c.d  
> bcdedit /set hypervisordebug on  

> NOTE: Set the `hostip` and `port` according to your environment

### **Host**
For the host, we can use `Windows 10 Anniversary Update (version 1607)` **or newer** (including **any Windows 11 version**). This requirement is because we are going to use the new [WinDbg](https://aka.ms/windbg/download).  

## **Hyper-V Reverse-Engineering**
[Hyper-V](https://en.wikipedia.org/wiki/Hyper-V) technology is both extensive and complex, encompassing numerous components. As the title suggests, our focus will be on `hvix64.exe`, the essential core of the Windows hypervisor specifically designed for Intel processors. Although `hvix64.exe` lacks symbols—which might seem like a disadvantage (or perhaps a twist of fate that brought us here) — we do have an older version[^1] with symbols available.  
Thankfully, insights into the [internals](https://hvinternals.blogspot.com/2021/01/hyper-v-debugging-for-beginners-2nd.html) of Hyper-V have been [provided](https://msrc.microsoft.com/blog/2018/12/first-steps-in-hyper-v-research/)  by various researchers. Furthermore, a researcher named [Gerhart](https://x.com/gerhart_x) advised in his [blog post](https://hvinternals.blogspot.com/2021/01/hyper-v-debugging-for-beginners-2nd.html) to conduct a bindiff of `hvix64.exe` with binaries such as `winload.efi` and older versions of `hvloader.dll`, as they share some of the same functionality in their code. Additionally, he published an [IDAPython script](https://github.com/gerhart01/Hyper-V-scripts/blob/master/ida75/ida75_CreatemVmcallHandlersTableWin11Preview.py) that locates essential information in `hvix64.exe`. For further resources on Hyper-V internals, you can check out [this link](https://github.com/gerhart01/Hyper-V-Internals/blob/master/HyperResearchesHistory.md).  

> Before diving into your own research, it's always worth reviewing past research. This can help you gain a better understanding and might also provide useful tools for your own research.  

## **Hyper-V Hypercall Interface**
In addition, the [Hypervisor Top Level Functional Specification](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs) (TLFS) provides us with detailed information about the [Hypercall Interface](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface). In this post, we are going to focus on the VTL Call.  

### **Secure Kernel (SK) Calls**
The NT kernel (`NTOS`, `ring0VTL0`) can access secure services provided by the Secure Kernel (`ring0VTL1`) by issuing a `VTL call`, which involves transitioning from `VTL0` to `VTL1`. This process is initiated by `NTOS` using a hypercall with the call code `0x11`, known as the [HvCallVtlCall](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/hvcallvtlcall) hypercall. Each secure service is uniquely identified by a `secure service call number` (`SSCN`).  

> In this post, the terms SK Call and VTL Call are used interchangeably; they mean the same thing.  

> For more information about [VSM](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm) and [VTL](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm#virtual-trust-level-vtl), please refer to [this link](https://blog.quarkslab.com/a-virtual-journey-from-hardware-virtualization-to-hyper-vs-virtual-trust-levels.html).  

To execute [HvCallVtlCall](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/hvcallvtlcall), `NTOS` uses the function chain `VslpEnterIumSecureMode`, which calls `HvlSwitchToVsmVtl1`, which in turn calls `HvlpSwitchToVsmVtl1RetpolineHelper`, ultimately jumping to `HvlpVsmVtlCallVa`. `HvlpVsmVtlCallVa` is a global variable that points to the hypercall page trampoline for issuing the `0x11` hypercall. `NTOS` functions that require secure services call `VslpEnterIumSecureMode`.  

`VslpEnterIumSecureMode`, like the other functions mentioned above, is undocumented[^2]. However, fortunately, there is quite a bit of [information](https://connormcgarr.github.io/secure-images/) about it [available](https://hal.science/hal-03117362v1/file/vsm_communication_signed.pdf) [online](https://windows-internals.com/hyperguard-secure-kernel-patch-guard-part-1-skpg-initialization/). `VslpEnterIumSecureMode` takes four arguments: the first parameter is of type `unsigned int8`, the second is `unsigned int16`, the third is `int`, and the fourth is `PVOID`. `NTOS` specifies the `SSCN` as the **second argument** to the `VslpEnterIumSecureMode` function.  

In addition, as noted in Windows Internals[^2], the `VslpEnterIumSecureMode` function receives a parameter that points to a `104` (`0x68`) byte data structure known as `SKCALL`. 
`SKCALL` describes the `operation type` (such as invoking a secure service, flushing the TB, resuming a thread, or calling an [enclave](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves)), the `SSCN`, and up to `12` qword parameters. Note that `SKCALL` should contain the `SSCN`, so we expect `VslpEnterIumSecureMode` or another function in the call chain to write it there. We'll look at this soon.  

We can verify these two parameters by examining the code.  
 
![](/assets/images/sk_calls_hvix64/ntos_VslApplySecureImageFixups.png)

In blue - `SKCALL` argument.  
In red - `SSCN`.  

The verification of the `SSCN` can be performed by examining the code of `securekernel!IumInvokeSecureService`, which includes symbols. This function contains a large switch case that identifies the `SSCN`:  

![](/assets/images/sk_calls_hvix64/sk_SkmmApplySecureFixups.png)

I was curious about the number of calls made to the `VslpEnterIumSecureMode` function and their specific details. Initially, I manually examined some of these calls and noticed that in almost all cases, the first argument is set to `2`, while the third argument is set to `0`.  
In `ntoskrnl.exe`[^3] on the guest machine, there are at least `158` references to the `VslpEnterIumSecureMode` function. Therefore, I decided to write an IDAPython script to analyze these calls and save the results to a file.  

```python
"""
Author: Dor00tkit (https://github.com/Dor00tkit/)
Date: October 14, 2024
Description: This Python script analyzes decompiled code to find and list all calls to a specified function, 
and writes the results to a text file.

The output file will contain lines in the following format:
- Calling Function: The name of the function that makes the call.
- Call: The call to the target function, including its arguments.

Example output:
KeBalanceSetManager: VslpEnterIumSecureMode(2u, 0xD1, 0, (__int64)v17)
VslExchangeEntropy: VslpEnterIumSecureMode(2u, 0x22, 0, (__int64)v4)
"""

import ida_hexrays
import idautils
import ida_xref
import idaapi
import idc


def get_all_xref_to(addr) -> list:
    """
    Retrieves all cross-references (xrefs) to a specified address.

    This function iterates through all cross-references to the given address and
    collects them in a list.

    :param int addr: The address to find cross-references to.
    :return: List of xrefs to the specified address
    """
    all_xref_to = []

    for ref in idautils.XrefsTo(addr):
        all_xref_to.append(ref)

    return all_xref_to


def trace_function_calls(target_func_name):
    """
    Traces all calls to a specified target function and writes the output to a text file.

    The function identifies the addresses of all calls to the target function within the
    decompiled code, retrieves the calling function names, and writes the call details
    to an output file.

    :param str target_func_name: The name of the target function to trace
    :return:
    """

    xref_to_target = []
    output = []
    target_func_addr = idaapi.get_name_ea(0, target_func_name)
    if target_func_addr == idaapi.BADADDR:
        print(f"Can`t find {target_func_name}. Abort!")
        return

    xref_to_target = get_all_xref_to(target_func_addr)
    print(f"[+] Found {len(xref_to_target)} xref to {target_func_name}")
    ida_hexrays.init_hexrays_plugin()

    for idx, xref in enumerate(xref_to_target):
        # ida_xref.fl_CN = Call Near, ida_xref.fl_JF = Jump Far
        if xref.type == ida_xref.fl_CN or xref.type == ida_xref.fl_JF:
            # print(f"[DEBUG] #{idx + 1} current xref: {hex(xref.frm)}")
            # print(f"[DEBUG] #{idx + 1} get_func({hex(xref.frm)}): {hex(f.start_ea)}\n")
            f = idaapi.get_func(xref.frm)

            idaapi.open_pseudocode(xref.frm, ida_hexrays.OPF_REUSE)
            cfunc = ida_hexrays.decompile(xref.frm)

            for cf in cfunc.treeitems:
                if cf.op == idaapi.cot_call:
                    if 'obj_ea' in cf.cexpr.x.operands:
                        if cf.cexpr.x.operands['obj_ea'] == target_func_addr:
                            print(f"[DEBUG] Found a call to ({target_func_name})\n")
                            decompiled_call_string = cf.cexpr.dstr()
                            called_from = idc.get_func_name(f.start_ea)
                            output.append(f"{called_from}: {decompiled_call_string}")

    if output:
        with open(f"output_{target_func_name}.txt", 'w') as file:
            file.write("\n".join(output) + "\n")


def main():
    trace_function_calls("VslpEnterIumSecureMode")


if __name__ == '__main__':
    main()

```

After filtering out duplicates, the analysis [revealed](https://gist.github.com/Dor00tkit/344ec1ff23f23ff036476a00c1320d97) that nearly all calls to `VslpEnterIumSecureMode` have `2` as the **first argument** and `0` as the **third argument**. However, only **3** out of the **156** calls use different values for the **first** and **third** arguments:  
```c
PspSecureThreadStartup: VslpEnterIumSecureMode(0, 0, KeGetCurrentThread()->SecureThreadCookie, (__int64)v9)
VslCallEnclave: VslpEnterIumSecureMode(1u, 0, *a2, (__int64)v17)
MiFlushEntireTbDueToAttributeChange: VslpEnterIumSecureMode(3u, 0, 0, (__int64)v1)
```

Based on our understanding, the **first argument** likely represents the `operation type`. For example:   
* `0` - resuming a thread.  
* `1` - call to an [enclave](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves).  
* `2` - invoking a secure service.  
* `3` - flushing the TB.

```c
NTSTATUS __fastcall VslpEnterIumSecureMode(unsigned __int8 operation_type, __int16 sscn, int a3, PVOID SKCALL) {
    __int16 _operation_type;     // r15
    char v7;                     // r13
    unsigned __int8 CurrentIrql; // r14
    __int16 v9;                  // dx
    __int64 v11;                 // r9
    char v39;                    // [rsp+3Ah] [rbp-37h]
    int _a3;                     // [rsp+40h] [rbp-31h]
    __int64 v47;                 // [rsp+58h] [rbp-19h]

    _operation_type = operation_type;
    _a3 = a3;
    v7 = 0;
    v39 = 0;
    CurrentIrql = 0xF;
    if (!(unsigned __int8)HvlQueryVsmConnection(0))
        return STATUS_DEVICE_NOT_CONNECTED;
    *(_BYTE *)v11 = _operation_type; // [1]
    *(_WORD *)(v11 + 2) = v9; // [2]
    v47 = *(_QWORD *)&KeGetCurrentThread()[1].CurrentRunTime;

    /* ... (code omitted for brevity) ... */
}
```

**At [1]**, the `operation_type` is set to the byte at `offset 0` of the `SKCALL` data structure (with `v11` pointed to by the `R9` register, which contains the `SKCALL` argument). Subsequently, **at [2]**, the `SSCN` (located in the `(R)DX` register) is assigned to `offsets 2-3` (stored as an int16) of the `SKCALL` data structure. This will assist us later in identifying `SKCALL`.  

Here’s an interesting snippet I encountered while reviewing the `VslpEnterIumSecureMode` function:  
```c
NTSTATUS __fastcall VslpEnterIumSecureMode(unsigned __int8 operation_type, __int16 sscn, int a3, SKCallData* SKCALL) {

    /* ... (code omitted for brevity) ... */

LABEL_67:
    if (SKCALL->sscn < xmmword_140E018D0) {
        /* ... (code omitted for brevity) ... */
    }

    /* ... (code omitted for brevity) ... */
}
```

We can see that the SSCN is compared to the global variable `xmmword_140E018D0`. Let’s examine the xref to `xmmword_140E018D0`:  

![](/assets/images/sk_calls_hvix64/xrefto_xmmword_140E018D0.png)

The global variable `xmmword_140E018D0` is initialized in `KiInitSystem`:   

![](/assets/images/sk_calls_hvix64/init_xmmword_140E018D0.png)

`xmmword_140E018D0` is initialized with the value of the global variable [KiServiceLimit](https://www.infosecinstitute.com/resources/hacking/hooking-system-service-dispatch-table-ssdt/), representing the total number of system calls in `NTOS`. However, verification reveals a discrepancy: the number of secure services, as indicated by the `securekernel!IumInvokeSecureService` switch case, is lower than the `KiServiceLimit` value. The function `securekernel!IumInvokeSecureService` supports fewer secure services than the `KiServiceLimit` would suggest.  

Let’s trace the `SKCALL` argument and observe how it is passed along the call chain until it reaches the [VMCALL](https://www.felixcloutier.com/x86/vmcall) instruction:  
```c
NTSTATUS __fastcall VslpEnterIumSecureMode(unsigned __int8 operation_type, __int16 sscn, int a3, SKCallData *SKCALL) {

    /* ... (code omitted for brevity) ... */
	
	HvlSwitchToVsmVtl1(0, SKCALL, v47);

    /* ... (code omitted for brevity) ... */
}
```

`SKCALL` is passed as the **second argument** (`RDX`) to `HvlSwitchToVsmVtl1`.  
Moving to `HvlSwitchToVsmVtl1`:  
```c
__int64 __fastcall HvlSwitchToVsmVtl1(__int64 a1, SKCallData *a2_SKCALL, __int64 a3) {

    /* ... (code omitted for brevity) ... */

    result = (*&HvlpVsmVtlCallVa)(a1, a2_SKCALL, KeGetCurrentIrql(), a3);

    /* ... (code omitted for brevity) ... */
}
```

The **second argument**, our `SKCALL` (`RDX`), is passed unchanged to `HvlpVsmVtlCallVa`. As observed in the decompilation, IDA has optimized out `HvlpSwitchToVsmVtl1RetpolineHelper`, which simply jumps to `HvlpVsmVtlCallVa`. Additionally, an examination of the disassembly reveals that the first qword from `SKCALL` is stored in the `RBX` register.  

Regarding the examination of `HvlpVsmVtlCallVa`, it can be a bit tricky because it is initialized at runtime. We have two options:
1. **Static Analysis**: We need to carefully trace the initialization of `HvlpVsmVtlCallVa`. This involves examining its setup in `ntoskrnl` and `hvix64` as well. You can refer to the section on [Establishing the Hypercall Interface](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface#establishing-the-hypercall-interface) for details on how this mechanism is initialized.  

2. **Dynamic Analysis**: Alternatively, you could choose dynamic analysis, which may be a simpler approach. Using the kernel debugger:  
```
kd> u poi(nt!HvlpVsmVtlCallVa)
fffff800`0f60000f 488bc1          mov     rax,rcx
fffff800`0f600012 48c7c111000000  mov     rcx,11h
fffff800`0f600019 0f01c1          vmcall
fffff800`0f60001c c3              ret
fffff800`0f60001d 8bc8            mov     ecx,eax
fffff800`0f60001f b812000000      mov     eax,12h
fffff800`0f600024 0f01c1          vmcall
fffff800`0f600027 c3              ret
```

`HvlpVsmVtlCallVa` issues the `HvCallVtlCall` hypercall.  

In the next section, we will cover the process of inspecting SK calls during debugging `hvix64.exe`.  

## **Inspecting SK Calls while debugging hvix64.exe**
And now, the real fun starts!  

### **Where should we start?**
A good starting point is to consider looking at [HvCallVtlCall](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/hvcallvtlcall). Since `hvix64.exe` does not include symbols, finding `HvCallVtlCall` might seem challenging. However, as described in [First Steps in Hyper-V Research](https://msrc.microsoft.com/blog/2018/12/first-steps-in-hyper-v-research/), Hyper-V organizes its hypercalls in a table located in the `CONST` section. Additionally, as previously mentioned, there is an [IDAPython script](https://github.com/gerhart01/Hyper-V-scripts/blob/master/ida75/ida75_CreatemVmcallHandlersTableWin11Preview.py) that can locate the hypercalls.  

`hvix64!HvCallVtlCall`:
```c
HV_STATUS __fastcall HvCallVtlCall(__int64 a1, __int64 a2, __int64 a3) {
    unsigned __int16 v3; // bx
    int v5;              // eax
    bool v6;             // zf
    int v7;              // esi
    __int64 v8;          // r8
    unsigned int v9;     // edx

    v3 = 0;
    v5 = 1 << *(*(a1 + 0x340) + 0x14);
    v6 = !_BitScanForward(&v7, *(a1 + 0x140) & ~(v5 | (v5 - 1)));
    if (v6 || a3) {
        return HV_STATUS_GUEST_INVALID_OPCODE_FAULT;
    } else {
        sub_FFFFF812A752C9D4();
        sub_FFFFF812A7527F04(a1, v7);
        v8 = *(a1 + 8 * v7 + 0x328);
        *(a1 + 0x348) |= 1 << v7;
        _BitScanReverse(&v9, *(a1 + 0x348));
        *(a1 + 0x34C) = v9;
        *(*(v8 + 0x30) + 8) = 1;
    }
    return v3;
}
```

At first glance, it seems challenging to grasp what is truly happening in this code. The parameters being passed are unknown. Moreover, if you review the [HvCallVtlCall](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/hvcallvtlcall) documentation, you will notice that it does not take any parameters. But how does that make sense? The function’s **primary job is to perform the VTL switch**, ignoring the parameters passed by `NTOS`, as they are intended for the `securekernel`.

What is our next step? Consider this: if we can identify the original `RDX` value at the moment of the `VMCALL` within the context of the `HvCallVtlCall` function, we can determine which `SSCN` is involved. However, to achieve this, we will need to trace the steps backward and connect the dots.

To observe the values of the registers immediately after the execution of the `VMCALL` instruction, we need to locate the [VM-Exit](https://dor00tkit.github.io/Dor00tkit/posts/learn-intel-vt-x-by-reversing-a-ctf-challenge/#vm-exit) handler.

### **Finding the VM-Exit Handler**
The easiest way to find the VM-Exit handler is to use a debugger. Stepping into the `VMCALL` instruction to enter the VMM context. This is similar to using a kernel debugger with the `SYSCALL` instruction. However, this method typically requires a JTAG debugger[^4] (or perhaps not? I will explore this topic further next year).

As suggested in [First Steps in Hyper-V Research](https://msrc.microsoft.com/blog/2018/12/first-steps-in-hyper-v-research/), before diving into dynamic analysis, we should begin with static analysis to gain a better understanding of the underlying mechanisms. This analysis will help us identify key functions, such as hypercalls (which we have already mapped out using the IDAPython script), the MSR read/write handler, the functions that interact with the VMCS, and the **VM-Exit handler**.

A highly effective technique for locating the VM-Exit handler and other relevant elements within the VMCS is to search for their write/read operations. For instance, in our case, we can search for the encoding value of the `HOST_RIP` field:

![](/assets/images/sk_calls_hvix64/searching_for_vm_exit_handler.png)

As you can see, there are not too many results, which is beneficial. Some of these can be disregarded, as they are related to the VMREAD instruction or are part of an array that includes other VMCS field encodings.
The following result appears promising:

![](/assets/images/sk_calls_hvix64/vmwrite_vmcs_host_rip.png)
`loc_FFFFF8000023C30B` (RVA: `0x23C30B`): 
![](/assets/images/sk_calls_hvix64/hvix64_vm_exit_handler_host_rip.png)

As observed, the snippet begins by saving the general-purpose registers (GPR) and the XMM registers, which is a positive indication. To confirm that it is the VM-Exit handler, we will need to verify it through a debugger:

![](/assets/images/sk_calls_hvix64/windbg_bp_vmcs_host_rip.png)

Some of you might wonder why I chose a software breakpoint (`0xCC`) over a hardware breakpoint.  
The answer is that, despite my attempts, hardware breakpoints failed to work, so I explored the [Intel SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) (Volume 3) to determine if I missed something. In the `VM Exits` chapter, there is a section called `Loading Host State`, which includes a sub-section named `Loading Host Control Registers, Debug Registers, MSRs` that contains the following:
> **28.5.1 Loading Host Control Registers, Debug Registers, MSRs**  
VM exits load new values for controls registers, debug registers, and some MSRs:  
[... omitted for brevity ...]  
* DR7 is set to 400H  

This action will cause the hardware breakpoints to be reset.

> I might be wrong, and the explanation could be entirely different. If anyone has insights to share, I’d be glad to hear them.

As we observe what happens next, we will see that the VM-Exit handler reads the `Exit reason` field quite early (lines 60-61) :  
```nasm
.text:FFFFF8000023C30B loc_FFFFF8000023C30B:                   ; DATA XREF: sub_FFFFF80000341E80+19↓o
.text:FFFFF8000023C30B                                         ; sub_FFFFF80000355098+B6↓o ...
.text:FFFFF8000023C30B                 mov     dword ptr [rsp+30h], 0
.text:FFFFF8000023C313
.text:FFFFF8000023C313 loc_FFFFF8000023C313:                   ; CODE XREF: sub_FFFFF8000023C000+432↓j
.text:FFFFF8000023C313                                         ; sub_FFFFF8000023C000+43F↓j
.text:FFFFF8000023C313                 mov     [rsp+28h], rcx
.text:FFFFF8000023C318                 mov     rcx, [rsp+20h]
.text:FFFFF8000023C31D                 mov     rcx, [rcx]
.text:FFFFF8000023C320                 mov     [rcx], rax
.text:FFFFF8000023C323                 mov     [rcx+10h], rdx
.text:FFFFF8000023C327                 mov     [rcx+18h], rbx
.text:FFFFF8000023C32B                 mov     [rcx+28h], rbp
.text:FFFFF8000023C32F                 mov     [rcx+30h], rsi
.text:FFFFF8000023C333                 mov     [rcx+38h], rdi
.text:FFFFF8000023C337                 mov     [rcx+40h], r8
.text:FFFFF8000023C33B                 mov     [rcx+48h], r9
.text:FFFFF8000023C33F                 mov     [rcx+50h], r10
.text:FFFFF8000023C343                 mov     [rcx+58h], r11
.text:FFFFF8000023C347                 mov     [rcx+60h], r12
.text:FFFFF8000023C34B                 mov     [rcx+68h], r13
.text:FFFFF8000023C34F                 mov     [rcx+70h], r14
.text:FFFFF8000023C353                 mov     [rcx+78h], r15
.text:FFFFF8000023C357                 mov     rax, [rsp+28h]
.text:FFFFF8000023C35C                 mov     [rcx+8], rax
.text:FFFFF8000023C360                 lea     rax, [rcx+70h]
.text:FFFFF8000023C364                 movaps  xmmword ptr [rax+10h], xmm0
.text:FFFFF8000023C368                 movaps  xmmword ptr [rax+20h], xmm1
.text:FFFFF8000023C36C                 movaps  xmmword ptr [rax+30h], xmm2
.text:FFFFF8000023C370                 movaps  xmmword ptr [rax+40h], xmm3
.text:FFFFF8000023C374                 movaps  xmmword ptr [rax+50h], xmm4
.text:FFFFF8000023C378                 movaps  xmmword ptr [rax+60h], xmm5
.text:FFFFF8000023C37C                 mov     rdx, [rsp+20h]
.text:FFFFF8000023C381                 xor     r8d, r8d
.text:FFFFF8000023C384                 xor     r9d, r9d
.text:FFFFF8000023C387                 xor     r10d, r10d
.text:FFFFF8000023C38A                 xor     r11d, r11d
.text:FFFFF8000023C38D                 pxor    xmm0, xmm0
.text:FFFFF8000023C391                 pxor    xmm1, xmm1
.text:FFFFF8000023C395                 pxor    xmm2, xmm2
.text:FFFFF8000023C399                 pxor    xmm3, xmm3
.text:FFFFF8000023C39D                 pxor    xmm4, xmm4
.text:FFFFF8000023C3A1                 pxor    xmm5, xmm5
.text:FFFFF8000023C3A5                 xor     ebp, ebp
.text:FFFFF8000023C3A7                 xor     ebx, ebx
.text:FFFFF8000023C3A9                 xor     esi, esi
.text:FFFFF8000023C3AB                 xor     edi, edi
.text:FFFFF8000023C3AD                 xor     r12d, r12d
.text:FFFFF8000023C3B0                 xor     r13d, r13d
.text:FFFFF8000023C3B3                 xor     r14d, r14d
.text:FFFFF8000023C3B6                 xor     r15d, r15d
.text:FFFFF8000023C3B9                 mov     [rsp+28h], rbx
.text:FFFFF8000023C3BE                 and     byte ptr gs:74h, 0F9h
.text:FFFFF8000023C3C7                 call    sub_FFFFF800002396E0
.text:FFFFF8000023C3CC                 mov     byte ptr gs:75h, 0
.text:FFFFF8000023C3D5                 mov     rcx, [rsp+20h]
.text:FFFFF8000023C3DA                 mov     byte ptr [rcx-0A7Bh], 0
.text:FFFFF8000023C3E1                 test    byte ptr cs:dword_FFFFF8000003F720, 1
.text:FFFFF8000023C3E8                 jnz     short loc_FFFFF8000023C3F7
.text:FFFFF8000023C3EA                 mov     eax, 4402h
.text:FFFFF8000023C3EF                 vmread  rsi, rax
.text:FFFFF8000023C3F2                 movzx   esi, si
.text:FFFFF8000023C3F5                 jmp     short loc_FFFFF8000023C407
```

Here is a command to log the VM-exit reason:  
```
bp hv+0x23c3f2 ".printf \"VM-Exit Reason(%x)\\n\", @si; gc"
```

Here is a command to set a conditional breakpoint when the VM-Exit reason equals `0x12` (`VMCALL`):  
```
bp hv+0x23c3f2 ".if (@esi == 0x12) {.echo Break on VMCALL} .else {gc}"
```

So, what is the next step? We should trace the process of how the general-purpose registers (GPRs) are preserved and then determine how to access them in the context of the `HvCallVtlCall` function.

> You might wonder why a conditional breakpoint on the VM-Exit reason is not used. The main issue is that the location of this breakpoint tends to be very noisy and inefficient. Additionally, hitting this breakpoint does not necessarily indicate that it is due to the `HvCallVtlCall` hypercall, as there are many other hypercalls that require additional conditions, making the conditional breakpoint more complicated.

### **Tracking GPRs State**
Let’s revisit the VM-Exit entrypoint:  
```nasm
.text:FFFFF8000023C30B loc_FFFFF8000023C30B:                   
.text:FFFFF8000023C30B                                         
.text:FFFFF8000023C30B                 mov     dword ptr [rsp+30h], 0
.text:FFFFF8000023C313
.text:FFFFF8000023C313 loc_FFFFF8000023C313:                   
.text:FFFFF8000023C313                                         
.text:FFFFF8000023C313                 mov     [rsp+28h], rcx  ; [1]
.text:FFFFF8000023C318                 mov     rcx, [rsp+20h]  ; [2]
.text:FFFFF8000023C31D                 mov     rcx, [rcx]      ; [3]
.text:FFFFF8000023C320                 mov     [rcx], rax      ; [4]
.text:FFFFF8000023C323                 mov     [rcx+10h], rdx
.text:FFFFF8000023C327                 mov     [rcx+18h], rbx
.text:FFFFF8000023C32B                 mov     [rcx+28h], rbp
.text:FFFFF8000023C32F                 mov     [rcx+30h], rsi
.text:FFFFF8000023C333                 mov     [rcx+38h], rdi
.text:FFFFF8000023C337                 mov     [rcx+40h], r8
.text:FFFFF8000023C33B                 mov     [rcx+48h], r9
.text:FFFFF8000023C33F                 mov     [rcx+50h], r10
.text:FFFFF8000023C343                 mov     [rcx+58h], r11
.text:FFFFF8000023C347                 mov     [rcx+60h], r12
.text:FFFFF8000023C34B                 mov     [rcx+68h], r13
.text:FFFFF8000023C34F                 mov     [rcx+70h], r14
.text:FFFFF8000023C353                 mov     [rcx+78h], r15  ; [5]
.text:FFFFF8000023C357                 mov     rax, [rsp+28h]  ; [6]
.text:FFFFF8000023C35C                 mov     [rcx+8], rax    ; [7]
.text:FFFFF8000023C360                 lea     rax, [rcx+70h]
.text:FFFFF8000023C364                 movaps  xmmword ptr [rax+10h], xmm0
.text:FFFFF8000023C368                 movaps  xmmword ptr [rax+20h], xmm1
.text:FFFFF8000023C36C                 movaps  xmmword ptr [rax+30h], xmm2
.text:FFFFF8000023C370                 movaps  xmmword ptr [rax+40h], xmm3
.text:FFFFF8000023C374                 movaps  xmmword ptr [rax+50h], xmm4
.text:FFFFF8000023C378                 movaps  xmmword ptr [rax+60h], xmm5
                                 ; ... (code omitted for brevity) ... 
								
.text:FFFFF8000023C3D5                 mov     rcx, [rsp+20h] ; [8]

                                 ; ... (code omitted for brevity) ... 
.text:FFFFF8000023C3EA                 mov     eax, 4402h ; Exit Reason
.text:FFFFF8000023C3EF                 vmread  rsi, rax
.text:FFFFF8000023C3F2                 movzx   esi, si
.text:FFFFF8000023C3F5                 jmp     short loc_FFFFF8000023C407
.text:FFFFF8000023C407 loc_FFFFF8000023C407:
.text:FFFFF8000023C407                 cmp     si, 1 ; EXIT_REASON_EXTERNAL_INTERRUPT
.text:FFFFF8000023C40B                 jnz     short loc_FFFFF8000023C417
.text:FFFFF8000023C40D                 call    sub_FFFFF8000023B690
.text:FFFFF8000023C412                 mov     rcx, [rsp+20h]
.text:FFFFF8000023C417
.text:FFFFF8000023C417 loc_FFFFF8000023C417:                   ; CODE XREF: sub_FFFFF8000023C000+40B↑j
.text:FFFFF8000023C417                 sti
.text:FFFFF8000023C418                 mov     edx, esi              ; [9]
.text:FFFFF8000023C41A                 or      edx, [rsp+30h]
.text:FFFFF8000023C41E                 call    sub_FFFFF80000216FA0  ; [10]
.text:FFFFF8000023C423                 jmp     loc_FFFFF8000023C140
```

**At [1]**, the value of `RCX` is saved at `[RSP+28h]` to preserve it. **At [2]**, `RCX` is loaded with the address of an internal `hvix64` data structure from `[RSP+20h]` (referred to as `hvix_ctx`). **At [3]**, `RCX` is dereferenced to access the `guest_saved_state` data structure. The `guest_saved_state` is a dedicated data structure allocated by `hvix64` for storing the guest GPRs and XMM registers. Between **[4] and [5]**, various GPRs are saved into the `guest_saved_state` structure. **At [6] and [7]**, the previously saved value of `RCX` (from step **[1]**) is saved into the `guest_saved_state` structure.

**Next, at [8]**, `RCX` is reloaded with the address of the `hvix_ctx` structure from `[RSP+20h]`. **At [9]**, the `ESI` register, which contains the `Exit reason`, is copied to `EDX`. Finally, **at [10]**, the function `sub_FFFFF80000216FA0` is called with the `hvix_ctx` structure as the **first argument** and the `Exit reason` as the **second argument**.

The `hvix_ctx` data structure is pre-allocated for each logical processor and is used to store critical data structures necessary for managing the virtual machines. Currently, we know that the `guest_saved_state` structure is located at offset `0` within this structure.

Moving on to `sub_FFFFF80000216FA0`, this function is extensive and is designed to parse the `Exit reason` and handle the VM-Exit appropriately. It parses the `Exit reason` using a comprehensive switch case statement that is quite noticeable:  
```c
__int64 __fastcall sub_FFFFF80000216FA0(unsigned int **a1, unsigned int a2) {
	/* ... (code omitted for brevity) ... */
	/* ... (code omitted for brevity) ... */
	/* ... (code omitted for brevity) ... */
    switch (a2) {
        case EXIT_REASON_MSR_WRITE:
		/* ... (code omitted for brevity) ... */

        case EXIT_REASON_EXTERNAL_INTERRUPT:
		/* ... (code omitted for brevity) ... */

        case EXIT_REASON_VMCALL:
            *(_DWORD *)(*(_QWORD *)(v6 + 0x108) + 0x178) = 9;
            v25 = *(char *)(*(_QWORD *)(v6 + 0x388) + 0xE0) < 0;
            v26 = *(_QWORD *)(v6 + 0x340);
            if (*(_DWORD *)(v26 + 0x12A0) == 3) {
                v27 = 1;
                *(_BYTE *)(v6 + 0x18) = 1;
                if (v25) goto LABEL_221;
                *(_QWORD *)(v6 + 0x10) = *(_QWORD *)(*(_QWORD *)(v26 + 0x30) + 0x20);
                if ((*(_DWORD *)(v6 + 0x10) & 1) == 0) goto LABEL_221;
            } else {
                v27 = 0;
                *(_BYTE *)(v6 + 0x18) = 0;
            }
            v28 = *(_QWORD *)(v6 + 0x340);
            v174 = 0;
            if ((*(_BYTE *)(*(_QWORD *)(v28 + 0x10A8) + 0x138) & 1) != 0) {
                if (*(_BYTE *)(v28 + 0x10B0)) {
                    sub_FFFFF80000355ECC((unsigned int *)(v28 + 0x1080), 0x60002, &v174);
                    LOWORD(_RAX) = v174;
                } else {
                    v175 = 0;
                    if ((dword_FFFFF8000003F720 & 1) != 0) {
                        LODWORD(_RAX) = *(_DWORD *)(*(_QWORD *)&NtCurrentTeb()[0x1D].GdiTebBatch.Buffer[0xF2] + 0xC0);
                    } else {
                        _RAX = GUEST_SS_AR_BYTES;
                        __asm { vmread  rax, rax}
                        v28 = *(_QWORD *)(v6 + 0x340);
                        v175 = _RAX;
                    }
                }
                v31 = ((unsigned __int64)(unsigned __int16)_RAX >> 5) & 3;
            } else {
                v31 = 0;
            }
            if (!(v31 | ((*(_QWORD *)(*(_QWORD *)(v28 + 0x10A8) + 0x110) & 1) == 0))) {
                v32 = *(_QWORD *)&NtCurrentTeb()[0xA].StaticUnicodeBuffer[0x20];
                v174 = 0;
                if (*(_BYTE *)(*(_QWORD *)(v32 + 0x340) + 0x10B0)) {
                    sub_FFFFF80000355ECC((unsigned int *)(*(_QWORD *)(v32 + 0x340) + 0x1080), 0x60001, &v174);
                    LODWORD(_RDX) = v174;
                } else {
                    v182 = 0;
                    if ((dword_FFFFF8000003F720 & 1) != 0) {
                        LODWORD(_RDX) = *(_DWORD *)(*(_QWORD *)&NtCurrentTeb()[0x1D].GdiTebBatch.Buffer[0xF2] + 0xBC);
                    } else {
                        _RAX = GUEST_CS_AR_BYTES;
                        __asm { vmread  rdx, rax}
                        v28 = *(_QWORD *)(v6 + 0x340);
                        v182 = _RDX;
                    }
                }
                if ((_RDX & 0x10000) != 0) LOWORD(_RDX) = 0;
                v35 = ((unsigned __int16)_RDX &
                       ((unsigned __int64)*(unsigned int *)(*(_QWORD *)(v28 + 0x10A8) + 0x110) >> 1) & 0x2000) != 0;
                v192 = 0;
                v189 = v6;
                v191 = v35;
                v190 = 0;
                sub_FFFFF80000215080(v6, 0, v35, (unsigned int *)&v189);
                break;
            }
            if (!v27) {
                if (v25 && *(_BYTE *)(*(_QWORD *)(v6 + 0x388) + 0x3E46)) {
                    sub_FFFFF800002DB44C(v6, 0, 0);
                } else {
                    *(_QWORD *)(v6 + 0x14) = 6;
                    *(_BYTE *)(v6 + 0x10) = 0;
                    *(_QWORD *)(v6 + 0x20) = 0;
                    *(_DWORD *)v6 = 7;
                }
                break;
            }
        LABEL_221:
            sub_FFFFF8000037FEA0(v6, 0x12, 0, *(unsigned __int8 *)(v6 + 8));
            break;
        case EXIT_REASON_HLT:
		/* ... (code omitted for brevity) ... */
    }
	/* ... (code omitted for brevity) ... */
}
```

While examining the `VMCALL` handling reveals several operations that may not provide clear insights, it is noticeable that there are references to four functions: `sub_FFFFF80000355ECC` is referenced twice, while `sub_FFFFF80000215080`, `sub_FFFFF800002DB44C`, and `sub_FFFFF8000037FEA0` are each referenced once.

How do we determine which function to focus on? Fortunately, we have only four functions to consider, which is a relatively small number. We can examine them one by one in chronological order. Alternatively, and often more effectively, we can use dynamic analysis. In this case, setting a breakpoint in `HvCallVtlCall` and then examining the call stack can provide valuable insights:  

![](/assets/images/sk_calls_hvix64/windbg_HvCallVtlCall_callstack.png)

Correlate with IDA:  

![](/assets/images/sk_calls_hvix64/ida_return_from_sub_FFFFF80000215080.png)

`sub_FFFFF80000215080` appears to be the function we should focus on. Additionally, a brief examination reveals that it **references the global hypercalls table** (`HvCallTable`). This is a strong indication. Why? Because the hypervisor needs to parse the `RCX` register to determine the requested hypercall, as it holds the [relevant information](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface#hypercall-inputs). Bingo!  
Before reviewing `sub_FFFFF80000215080`, we must first understand the parameters that are passed to it:  
```c
/* ... (code omitted for brevity) ... */
v35 = ((unsigned __int16)_RDX &((unsigned __int64)*(unsigned int *)(*(_QWORD *)(v28 + 0x10A8) + 0x110) >> 1) & 0x2000) != 0;
v192 = 0;
v189 = v6;
v191 = v35;
v190 = 0;
sub_FFFFF80000215080(v6, 0, v35, &v189);
/* ... (code omitted for brevity) ... */
```

`v35` is a boolean, and `v189` contains `v6`. To determine the value of `v6`, we need to trace back through the code:  
```c
v6 = a1 + 0xFFFFFE40;
```

`a1` is the first argument of the current function (`sub_FFFFF80000216FA0`), pointing to the `hvix_ctx` structure. As previously mentioned, `hvix_ctx` contains a pointer to the `guest_saved_state` structure at offset `0`.  
But what is this strange access: `+ 0xFFFFFE40`? Let’s take a look at the disassembly of this instruction:  
```nasm
.text:FFFFF80000216FDE                 mov     r12, rcx
                            ; ... (code omitted for brevity) ... 
.text:FFFFF80000217009                 lea     rdi, [r12-0E00h]
```

`v6` is located `0xE00` bytes behind the start of the `hvix_ctx` structure.  

Moving to `sub_FFFFF80000215080`, although the function is complex, we will focus on how it accesses the global hypercalls table (`HvCallTable`):  
```c
__int64 __fastcall sub_FFFFF80000215080(__int64 a1, __int64 a2, __int64 a3, unsigned int *a4) {
	
    /* ... (code omitted for brevity) ... */

    if ((v16 & 0x80u) == 0 || sub_FFFFF800002A65D4(v14, v12, a3, v13)) {
        v17 = *((unsigned __int16 *)&HvCallTable + 0xC * (v12 & 0x3FFF) + 0xA);
        v18 = &HvCallTable + 3 * (v12 & 0x3FFF);
        ++*(_QWORD *)(*(_QWORD *)(*(_QWORD *)(a1 + 0x108) + 0x13B8) + 8 * v17);
        goto LABEL_16;
    }

    /* ... (code omitted for brevity) ... */
}
```

As you can see, `v12` is used when accessing `HvCallTable`. We need to track `v12`:  
```c
v12 = v44;
```

`v44`:  
```c
v44 = v10;
```

`v10`:   
```c
if (a3 > 1)
{
    v9 = a4 + 8;
}
else
{
    v9 = *(*a4 + 0xE00);
    if (!a3) 
    {
        v10 = *v9 | (*(v9 + 2) << 0x20);
        goto LABEL_4;
    }
}
v10 = *((_QWORD *)v9 + 1);
```

As you can see, `v9` depends on the **third argument**. If this argument is **greater than** `1`, the `if` code block will execute; otherwise, the `else` code block will execute. Since our **third argument** is a boolean (`v35`), the `else` block will execute regardless of whether it is set to `true`. Nevertheless, this can be easily verified using the debugger. Let’s see what happened with `v9` in the `else` block:  
```c
v9 = *(*a4 + 0xE00);
```

As a reminder, the **fourth argument** (`a4`) is a **pointer to** `v189`, which contains `v6`. As mentioned earlier, `v6` is positioned `0xE00` bytes behind the `hvix_ctx` structure. By evaluating `v9 = *(*a4 + 0xE00)`, we effectively navigate back to the `hvix_ctx` structure and dereference its first element, which points to the `guest_saved_state` structure. As a result, `v9` will point to the `guest_saved_state` structure.

Revisiting `v10`, the expression `v10 = *((_QWORD *)v9 + 1);` assigns the second element of the `guest_saved_state` structure to `v10`, which corresponds to the `RCX` register!  

> In IDA, we can import the following custom structure to improve the clarity of the decompiled code:  
```c
struct saved_state
{
    __int64 _RAX;
    __int64 _RCX;
    __int64 _RDX;
    __int64 _RBX;
    __int64 _RSP;
    __int64 _RBP;
    __int64 _RSI;
    __int64 _RDI;
    __int64 _R8;
    __int64 _R9;
    __int64 _R10;
    __int64 _R11;
    __int64 _R12;
    __int64 _R13;
    __int64 _R14;
    __int64 _R15;
    __int128 _XMM0;
    __int128 _XMM1;
    __int128 _XMM2;
    __int128 _XMM3;
    __int128 _XMM4;
    __int128 _XMM5;
};
```

To summarize, `v12` contains the saved `RCX` register. Let’s go back to examining the accesses to the global hypercalls table (`HvCallTable`) :  
```c
v17 = *((unsigned __int16 *)&HvCallTable + 0xC * (v12 & 0x3FFF) + 0xA);
v18 = &HvCallTable + 3 * (v12 & 0x3FFF);
++*(_QWORD *)(*(_QWORD *)(*(_QWORD *)(a1 + 0x108) + 0x13B8) + 8 * v17);
goto LABEL_16;
```

The expression `v12 & 0x3FFF` extracts `14` bits from `RCX`, corresponding to the `Call code` (bits 15-0) that specifies the requested hypercall. In our case `RCX` = `0x11` (`HvCallVtlCall`). Let’s carefully examine the expressions, as they involve pointer arithmetic, which can be quite tricky:  
*  `*((unsigned __int16 *)&HvCallTable + 0xC * (v12 & 0x3FFF) + 0xA);` - First, notice that `HvCallTable` is treated as an array of `unsigned __int16`. To access an element, compute the offset by multiplying `0xC` by `0x11`, adding `0xA`, and then multiplying the result by `2` because the element size is `unsigned __int16` (`2` bytes). The final result is: `0x1AC`.
*  `&HvCallTable + 3 * (v12 & 0x3FFF);` - This expression is simpler than the previous one. `HvCallTable` is treated as an array of function pointers, each `8` bytes in size. To access an element, calculate the offset by multiplying `0x3` by `0x11`, and then multiply the result by `8` to account for the `8-byte` size of each element. The final result is: `0x198`.

> In such cases, it is crucial to verify through disassembly that the expressions shown in the decompiled code are accurate.

![](/assets/images/sk_calls_hvix64/ida_HvCallTable_HvCallVtlCall.png)

We can ignore `v17` and focus on `v18`, which now points to `HvCallVtlCall`:  

![](/assets/images/sk_calls_hvix64/ida_sub_FFFFF80000215080_xref_to_v18.png)

Determining which cross-reference (xref) to focus on is easier, given that there are only four relevant ones. The last xref is particularly promising because it represents a function call. Applying the previous technique—setting a breakpoint on `HvCallVtlCall` and checking the call stack—helps confirm that the last xref is our target:

![](/assets/images/sk_calls_hvix64/windbg_HvCallVtlCall_callstack_2.png)

Correlate with IDA:  

![](/assets/images/sk_calls_hvix64/ida_return_from_v18.png)

```c
(*v18)(a1, v6, v35, v13)
```

According to the decompiled code, the current function (`sub_FFFFF80000215080`) uses its **first argument** (`a1`) as the **first argument** to `HvCallVtlCall`. As mentioned earlier, `a1` is positioned `0xE00` bytes behind the `hvix_ctx` structure. With this, we can now access the GPRs in the `HvCallVtlCall` context. In the `HvCallVtlCall` context, we take the value in the `RCX` register, add `0xE00` to it, and then dereference the address to access the first qword, which contains the `guest_saved_state` structure.

### **Detailed Walkthrough of SK Call Inspection**
Let’s see how this can be done with WinDbg:

![](/assets/images/sk_calls_hvix64/windbg_HvCallVtlCall_gprs.png)

If we attempt to access `SKCALL` memory directly, we will notice that it cannot be read:

![](/assets/images/sk_calls_hvix64/windbg_hvix_acc_gva.png)

The hypervisor cannot **directly** access a guest’s `Guest Virtual Address` (GVA) because the guest’s virtual address space is separate from the hypervisor’s address space. Instead, modern hypervisors utilize the [Second Level Address Translation](https://en.wikipedia.org/wiki/Second_Level_Address_Translation) mechanism to translate `Guest Physical Addresses` (GPAs) into `Host Physical Addresses` (HPAs) for accessing the corresponding memory.

> For a detailed explanation of how Second-Level Address Translation (SLAT) works in translating memory addresses, please refer to this [link](https://blog.quarkslab.com/a-virtual-journey-from-hardware-virtualization-to-hyper-vs-virtual-trust-levels.html).

Fortunately, instead of manually translating GPA to HPA, there are a few [scripts](https://github.com/ergot86/hyperv_stuff/blob/main/windbg_hyperv_script.js) that can assist. I chose to use [hvext](https://github.com/tandasat/hvext), created by [Satoshi Tanda](https://x.com/standa_t), which is still actively maintained.

> In addition, I modified `hvext` by adding two new commands: `!gva_to_hpa` and `!read_vmcs`.  
* `!gva_to_hpa` - Simplifies the translation process from GVA to HPA.  
* `!read_vmcs` - Reads a specific field from the VMCS using either the field name or its encoding value.  
  You can check out my modified [hvext](https://github.com/Dor00tkit/hvext) to see these changes in action.  

Translating `SKCALL` GVA to HPA:  
![](/assets/images/sk_calls_hvix64/windbg_skcall_gva_to_hpa.png)  

Start by translating the GVA to GPA, and then translate the GPA to HPA. However, as shown in the image above, you’ll notice that the GPA for `GUEST_CR3` directly matches the HPA. This one-to-one relationship is called identity-mapping, where GPA equals HPA. Therefore, for our purposes, translating the GVA to GPA alone is sufficient. Additionally, as shown in the image, we validated `SKCALL` by using the `RBX` value from the `guest_saved_state` structure.  

Based on the value of `SKCALL[0]` (`byte`, offset `0`), the `operation type` is invoking a secure service (value `2`). Additionally, `SKCALL[2]` (`int16`, offset `2`) is `0x1F`. Searching for this value (`0x1F`) in the `VslpEnterIumSecureMode` calls xref [results](https://gist.github.com/Dor00tkit/344ec1ff23f23ff036476a00c1320d97) (generated by the IDAPython script), reveals that this SK Call was invoked by `VslValidateDynamicCodePages`:  
```c
VslValidateDynamicCodePages: VslpEnterIumSecureMode(2u, 0x1F, 0, (__int64)v11)
```

## **Conclusion**
Investigating SK calls within `hvix64.exe` has revealed key insights into Hyper-V's inner workings. By analyzing the VM-Exit handler and hypercall interface, we uncovered how guest state information is managed in the hypervisor. Static analysis with IDA, combined with dynamic debugging using WinDbg and hvext, allowed us to examine SK calls in detail, including their types and secure service call numbers.  

## **Thanks**
[Connor McGarr](https://x.com/33y0re), [Gerhart](https://x.com/gerhart_x), [Saar Amar](https://x.com/AmarSaar), [Daniel Fernández](https://x.com/ergot86), [Satoshi Tanda](https://x.com/standa_t), [Aleksandar Milenkoski](https://x.com/milenkowski?lang=en), [Yarden Shafir](https://x.com/yarden_shafir), [Alan Sguigna](https://x.com/AlanSguigna).  
[OpenSecurityTraining2](https://ost2.fyi/) (OST2) :heart: .

## Recommended Reading
1. [Hypervisor Top Level Functional Specification](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs)
2. [Windows Internals Book](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals)
3. [Hyper-V debugging for beginners. 2nd edition](https://hvinternals.blogspot.com/2021/01/hyper-v-debugging-for-beginners-2nd.html)
4. [First Steps in Hyper-V Research](https://msrc.microsoft.com/blog/2018/12/first-steps-in-hyper-v-research/)
5. [ERNW Newsletter 43 - Security Assessment of Microsoft Hyper-V](https://static.ernw.de/whitepaper/ERNW_Newsletter_43_HyperV_en.pdf)
6. [Hyper-V internals researches history (2006-2024)](https://github.com/gerhart01/Hyper-V-Internals/blob/master/HyperResearchesHistory.md)
7. [A virtual journey: From hardware virtualization to Hyper-V's Virtual Trust Levels](https://blog.quarkslab.com/a-virtual-journey-from-hardware-virtualization-to-hyper-vs-virtual-trust-levels.html)
8. [Debugging Windows Isolated User Mode (IUM) Processes](https://blog.quarkslab.com/debugging-windows-isolated-user-mode-ium-processes.html)
9. [Virtual Secure Mode: Communication Interfaces](https://hal.science/hal-03117362v1/file/vsm_communication_signed.pdf)
10. [Intel SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
11. [Hypervisor From Scratch](https://rayanfam.com/topics/hypervisor-from-scratch-part-1/)
12. [5 Days to Virtualization: A Series on Hypervisor Development](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/)
13. [MMU Virtualization via Intel EPT](https://revers.engineering/mmu-virtualization-via-intel-ept-index/)

## Footnotes
[^1]: File version: `6.0.6001.17101`. SHA1: `a6428ca923dfec46d83a9432b253ecbd83b192f2`  
[^2]: In fact, it is briefly mentioned in the second volume of [Windows Internals](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals) in the seventh edition.  
[^3]: File version: `10.0.22621.2861`. SHA1: `520d387c25108dcc50cde78e710fd83582b614e3`  
[^4]: See [[1]](https://x.com/AlanSguigna/status/1824120348255625247), [[2]](https://ourwindowsman.wordpress.com/2021/09/03/what-dci-can-do-for-you-or-rather-cant/), [[3]](https://standa-note.blogspot.com/2021/03/debugging-system-with-dci-and-windbg.html) and [[4]](https://www.asset-intertech.com/resources/blog/2024/01/jtag-debug-of-windows-hyper-v-secure-kernel-with-windbg-and-exdi-part-1/).
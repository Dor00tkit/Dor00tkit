---
layout: post
title: "From Admin to Kernel: One Year, One Driver, Zero Attention"
date: "2024-09-24"
categories: 
  - "Reverse-Engineering"
  - "Vulnerability"
tags: 
  - "Admin-To-Kernel"
  - "DellInstrumentation.sys"
  - "CVE-2021-21551"
comments: true
---

## **Introduction & Motivation**
My little journey started with an exploration of third-party drivers to uncover possible vulnerabilities. While using the [System Informer](https://systeminformer.sourceforge.io/) tool to review the drivers active on my system, I discovered `DellInstrumentation.sys`.  

For over a year, `DellInstrumentation.sys` has remained under the radar, leaving a potential privilege escalation vulnerability from admin to kernel unexamined by the security community. This isn’t the first time Dell drivers have been vulnerable; in 2021, [CVE-2021-21551](https://www.sentinelone.com/labs/cve-2021-21551-hundreds-of-millions-of-dell-computers-at-risk-due-to-multiple-bios-driver-privilege-escalation-flaws/) exposed privilege escalation flaws in Dell’s BIOS driver, affecting millions of DELL devices.

## **Deja Vu Moment**
After beginning to reverse-engineer `DellInstrumentation.sys`, I had a strong sense of déjà vu. Not long ago, I analyzed `DBUtilDrv2.sys` (version 2.7), and the two drivers share many similarities. Both drivers utilize nearly identical IOCTLs and are [KMDF](https://en.wikipedia.org/wiki/Kernel-Mode_Driver_Framework)-based. However, `DBUtilDrv2.sys` is already known as a vulnerable driver. This raised the possibility that `DellInstrumentation.sys` might suffer from the same weaknesses, prompting me to dig deeper into its security flaws.  

## **Key Differences Between DellInstrumentation.sys and DBUtilDrv2.sys**
While `DellInstrumentation.sys` and `DBUtilDrv2.sys` share many similarities, several important differences stand out:  
* [Model-Specific Registers (MSR)](https://en.wikipedia.org/wiki/Model-specific_register) Support: Unlike `DBUtilDrv2.sys`, `DellInstrumentation.sys` includes functionality for reading Model-Specific Registers.   
IOCTL: `0x9B0C1E40`.  
![](/assets/images/dell/dellinstrumentation_readmsr.png)
* [PCI](https://en.wikipedia.org/wiki/Peripheral_Component_Interconnect) Access: Unlike `DBUtilDrv2.sys`, `DellInstrumentation.sys` includes functionality for accessing PCI devices.  
IOCTL: `0x9B0C1F48` and `0x9B0C1F4C`.  
![](/assets/images/dell/dellinstrumentation_accesspci.png)
* [DbgPrintEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgprintex) Usage: `DellInstrumentation.sys` makes extensive use of [DbgPrintEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgprintex) calls, which include function names and parameter names, providing deeper insight into the driver’s internal operations and functionality.
* [Symbolic Link Name](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/using-device-interfaces): The symbolic link for `DellInstrumentation.sys` is named `Dell_Instrumentation`, distinguishing it from the one used by `DBUtilDrv2.sys` (`DBUtil_2_5`).

## **Proof of Concept**
The PoC is very similar to [CVE-2021-21551 PoC](https://github.com/mathisvickie/CVE-2021-21551), you can find [my code on GitHub](https://github.com/Dor00tkit/DellInstrumentation_PoC).

## **Thanks**
[Kasif Dekel](https://x.com/kasifdekel), [mathisvickie](https://github.com/mathisvickie), [Paolo Stagno (aka VoidSec)](https://x.com/Void_Sec), [Takahiro Haruyama](https://x.com/cci_forensics).  
[OpenSecurityTraining2](https://ost2.fyi/) (OST2) :heart: .

## **Resources & References**
1. [CVE-2021-21551- Hundreds Of Millions Of Dell Computers At Risk Due to Multiple BIOS Driver Privilege Escalation Flaws](https://www.sentinelone.com/labs/cve-2021-21551-hundreds-of-millions-of-dell-computers-at-risk-due-to-multiple-bios-driver-privilege-escalation-flaws/)
2. [Reverse Engineering & Exploiting Dell CVE-2021-21551](https://voidsec.com/reverse-engineering-and-exploiting-dell-cve-2021-21551/)
3. [Exploit Development: CVE-2021-21551 - Dell ‘dbutil_2_3.sys’ Kernel Exploit Writeup](https://connormcgarr.github.io/cve-2020-21551-sploit/)
4. [Simple PoC for exploiting CVE-2021-21551 for LPE by spawning system cmd](https://github.com/mathisvickie/CVE-2021-21551)
5. [Hunting Vulnerable Kernel Drivers](https://blogs.vmware.com/security/2023/10/hunting-vulnerable-kernel-drivers.html)
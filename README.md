# riscv_vcpu
riscv_vcpu_te: Lightweight Virtual CPU Framework for RISC-V Virtualization
[![CI](https://github.com/arceos-hypervisor/riscv_vcpu/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/arceos-hypervisor/riscv_vcpu/actions/workflows/ci.yml)


Overview

riscv_vcpu_te implements a minimal RISC-V Virtual CPU (VCPU) abstraction layer compliant with the RISC-V Hypervisor Extension (RVH). Designed for embedded hypervisors and educational use, it operates in no_std environments with support for FPGA acceleration.

Features

• RVH Extension Support  

  Virtual registers (hstatus, htimedelta, vsstatus), interrupt virtualization, and context switching.  
• Bare-Metal & Simulator Friendly  

  Runs on TinyRISCV hardware or QEMU without OS dependency.  


Basic Usage

use riscv_vcpu_te::vcpu::VCPU;

let mut vcpu = VCPU::new();
vcpu.load_firmware(0x8000_0000); // Guest entry point
vcpu.execute(); // Start VM execution

  

License

• Core Code: Apache-2.0  

• Examples/Tools: MIT  

Full text in https://github.com/bullhh/riscv_vcpu_te/blob/main/LICENSE.  

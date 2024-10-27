use axerrno::{AxError, AxResult};
use axvcpu::AxArchPerCpu;
use riscv::register::sstatus;
use riscv::register::{hedeleg, hideleg, hvip, sie, stvec};

use crate::consts::traps;
use crate::consts::traps::irq::TIMER_IRQ_NUM;
use crate::has_hardware_support;

/// The architecture dependent configuration of a `AxArchPerCpu`.
pub struct RISCVPerCpu {}

impl AxArchPerCpu for RISCVPerCpu {
    fn new(cpu_id: usize) -> AxResult<Self> {
        unsafe {
            setup_csrs();
        }

        Ok(Self {})
    }

    fn is_enabled(&self) -> bool {
        unimplemented!()
    }

    fn hardware_enable(&mut self) -> AxResult<()> {
        if has_hardware_support() {
            Ok(())
        } else {
            Err(AxError::Unsupported)
        }
    }

    fn hardware_disable(&mut self) -> AxResult<()> {
        unimplemented!()
    }
}

/// Initialize (H)S-level CSRs to a reasonable state.
unsafe fn setup_csrs() {
    // Delegate some synchronous exceptions.
    hedeleg::Hedeleg::from_bits(
        traps::exception::INST_ADDR_MISALIGN
            | traps::exception::BREAKPOINT
            | traps::exception::ENV_CALL_FROM_U_OR_VU
            | traps::exception::INST_PAGE_FAULT
            | traps::exception::LOAD_PAGE_FAULT
            | traps::exception::STORE_PAGE_FAULT
            | traps::exception::ILLEGAL_INST,
    )
    .write();

    // Delegate all interupts.
    hideleg::Hideleg::from_bits(
        traps::interrupt::VIRTUAL_SUPERVISOR_TIMER
            | traps::interrupt::VIRTUAL_SUPERVISOR_EXTERNAL
            | traps::interrupt::VIRTUAL_SUPERVISOR_SOFT,
    )
    .write();

    // Clear all interrupts.
    hvip::clear_vssip();
    hvip::clear_vstip();
    hvip::clear_vseip();

    // clear all interrupts.
    // the csr num of hcounteren is 0x606, the riscv repo is error!!!
    // hcounteren::Hcounteren::from_bits(0xffff_ffff).write();
    core::arch::asm!("csrw {csr}, {rs}", csr = const 0x606, rs = in(reg) -1);

    // enable interrupt
    sie::set_sext();
    sie::set_ssoft();
    sie::set_stimer();
}
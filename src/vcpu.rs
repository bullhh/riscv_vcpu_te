use core::{default, panic};

use bitflags::Flag;
use riscv::register::{hideleg, hstatus, mstatus};
use riscv::register::{htinst, htval, hvip, scause, sie, sstatus, stval, hip, vsip, hie, vsie, mip, mie};
use riscv_decode::Instruction;
use rustsbi::{Forward, RustSBI};
use sbi_spec::{base, hsm, legacy, spi, time};
use timer_list::TimeValue;

use axaddrspace::{GuestPhysAddr, HostPhysAddr, HostVirtAddr, MappingFlags};
use axerrno::AxResult;
use axvcpu::{AxVCpuExitReason, SbiFunction};

use crate::consts::traps::interrupt::SUPERVISOR_TIMER;
use crate::regs::*;
use crate::{RISCVVCpuCreateConfig, EID_HVC};

extern "C" {
    fn _run_guest(state: *mut VmCpuRegisters);

    // fn _copy_to_guest(dest_gpa: usize, src: *const u8, len: usize) -> usize;
    // fn _copy_from_guest(dest: *mut u8, src_gpa: usize, len: usize) -> usize;
    fn _fetch_guest_instruction(gva: usize, raw_inst: *mut u32) -> isize;
}

core::arch::global_asm!(include_str!("mem_extable.S"));

/// The architecture dependent configuration of a `AxArchVCpu`.
#[derive(Clone, Copy, Debug, Default)]
pub struct VCpuConfig {}

static mut FLAG: u64 = 0;
static mut PRINT: u64 = 0;

// #[derive(Default)]
/// A virtual CPU within a guest
pub struct RISCVVCpu {
    regs: VmCpuRegisters,
    sbi: RISCVVCpuSbi,
    // ADDED
    hvip: hvip::Hvip,
}

#[derive(RustSBI)]
struct RISCVVCpuSbi {
    // timer: RISCVVCpuSbiTimer,
    #[rustsbi(console, pmu, fence, reset, info, hsm)]
    forward: Forward,
}

impl Default for RISCVVCpuSbi {
    #[inline]
    fn default() -> Self {
        Self {
            // timer: RISCVVCpuSbiTimer,
            forward: Forward,
        }
    }
}

// struct RISCVVCpuSbiTimer;

// impl rustsbi::Timer for RISCVVCpuSbiTimer {
//     #[inline]
//     fn set_timer(&self, stime_value: u64) {
//         sbi_rt::set_timer(stime_value);
//         // Clear guest timer interrupt
//         CSR.hvip
//             .read_and_clear_bits(traps::interrupt::VIRTUAL_SUPERVISOR_TIMER);
//         //  Enable host timer interrupt
//         CSR.sie
//             .read_and_set_bits(traps::interrupt::SUPERVISOR_TIMER);
//     }
// }

impl axvcpu::AxArchVCpu for RISCVVCpu {
    type CreateConfig = RISCVVCpuCreateConfig;

    type SetupConfig = ();

    fn new(config: Self::CreateConfig) -> AxResult<Self> {
        let mut regs = VmCpuRegisters::default();
        // Setup the guest's general purpose registers.
        // `a0` is the hartid
        regs.guest_regs.gprs.set_reg(GprIndex::A0, config.hart_id);
        // `a1` is the address of the device tree blob.
        regs.guest_regs
            .gprs
            .set_reg(GprIndex::A1, config.dtb_addr.as_usize());

        Ok(Self {
            regs: VmCpuRegisters::default(),
            sbi: RISCVVCpuSbi::default(),
            // ADDED
            hvip: hvip::Hvip::from_bits(0),
        })
    }

    fn setup(&mut self, _config: Self::SetupConfig) -> AxResult {
        // Set sstatus.
        let mut sstatus = sstatus::read();
        sstatus.set_spp(sstatus::SPP::Supervisor);
        self.regs.guest_regs.sstatus = sstatus.bits();

        // Set hstatus.
        let mut hstatus = hstatus::read();
        hstatus.set_spv(true);
        // Set SPVP bit in order to accessing VS-mode memory from HS-mode.
        hstatus.set_spvp(true);
        /// Set VTW to raise instruction exception wfi when wfi does not complete within an implementation-specific, bounded time limit(probably 0)
        // hstatus.set_vtw(true);
        
        unsafe {
            hstatus.write();
        }
        self.regs.guest_regs.hstatus = hstatus.bits();
        Ok(())
    }

    fn set_entry(&mut self, entry: GuestPhysAddr) -> AxResult {
        self.regs.guest_regs.sepc = entry.as_usize();
        Ok(())
    }

    fn set_ept_root(&mut self, ept_root: HostPhysAddr) -> AxResult {
        self.regs.virtual_hs_csrs.hgatp = 8usize << 60 | usize::from(ept_root) >> 12;
        Ok(())
    }

    fn run(&mut self) -> AxResult<AxVCpuExitReason> {

        unsafe {
            if PRINT > 0 {
                error!("before run hvip {:#x?} to phy hvip {:#x}", self.hvip.bits(), hvip::read().bits());
                // PRINT -= 1;
            }

        }

        unsafe {
            self.hvip.write();
        }

        assert!(self.hvip.bits() == hvip::read().bits());

        assert!(vsip::read().bits() == 0);

        unsafe {
            if PRINT > 0 {
                error!("before run hip {:#x?} & vsip {:#x?}", hip::read().bits(), vsip::read().bits());
                error!("before run hie {:#x?} & vsie {:#x?}", hie::read().bits(), vsie::read().bits());
                error!("hideleg: {:#x}", hideleg::read().bits());
                // error!("before run mip: {:#x}, mie:{:#x}", mip::read().bits(), mie::read().bits());
                
                PRINT -= 1;
            }

        }

        // if unsafe {FLAG += 1; FLAG} > 30000 {
        //     error!("before run {:#x?}", hvip::read().bits());
        // }

        unsafe {
            sstatus::clear_sie();
            sie::set_sext();
            sie::set_ssoft();
            sie::set_stimer();
        }

        

        // error!("before run {:#x?}", hvip::read().bits());
        // error!("before run");
        unsafe {
            // Safe to run the guest as it only touches memory assigned to it by being owned
            // by its page table
            _run_guest(&mut self.regs);
        }
        unsafe {
            sie::clear_sext();
            sie::clear_ssoft();
            sie::clear_stimer();
            sstatus::set_sie();
        }

        assert!(vsip::read().bits() == 0);

        unsafe {
            if PRINT > 0 {
                error!("after run hip {:#x?} & vsip {:#x?}", hip::read().bits(), vsip::read().bits());
                error!("after run hie {:#x?} & vsie {:#x?}", hie::read().bits(), vsie::read().bits());
                error!("hideleg: {:#x}", hideleg::read().bits());
                // error!("after run mip: {:#x}, mie:{:#x}", mip::read().bits(), mie::read().bits());
                PRINT -= 1;
            }

        }


        self.vmexit_handler()
    }

    fn bind(&mut self) -> AxResult {
        unsafe {
            core::arch::asm!(
                "csrw hgatp, {hgatp}",
                hgatp = in(reg) self.regs.virtual_hs_csrs.hgatp,
            );
            core::arch::riscv64::hfence_gvma_all();
        }
        Ok(())
    }

    fn unbind(&mut self) -> AxResult {
        Ok(())
    }

    /// Set one of the vCPU's general purpose register.
    fn set_gpr(&mut self, index: usize, val: usize) {
        match index {
            0..=7 => {
                self.set_gpr_from_gpr_index(GprIndex::from_raw(index as u32 + 10).unwrap(), val);
            }
            _ => {
                warn!(
                    "RISCVVCpu: Unsupported general purpose register index: {}",
                    index
                );
            }
        }
    }

    /// TEST: Assert irq
    fn notify_irq(&mut self, irq: usize) {
        match irq {
            5 => {
                self.hvip.set_vstip(true);
                // error!("a virq timer: {:#x}", self.hvip.bits());
                unsafe {
                    PRINT = 4;
                }
            }
            _ => {
                todo!("irq_no: {}", irq);
            }
        }
    }

    /// TEST: Assert irq
    fn denotify_irq(&mut self, irq: usize) {
        match irq {
            5 => {
                self.hvip.set_vstip(false);
                // error!("de virq timer: {:#x}", self.hvip.bits());
                unsafe {
                    PRINT = 4;
                }
            }
            _ => {
                todo!("irq_no: {}", irq);
            }
        }
    }

}

impl RISCVVCpu {
    /// Gets one of the vCPU's general purpose registers.
    pub fn get_gpr(&self, index: GprIndex) -> usize {
        self.regs.guest_regs.gprs.reg(index)
    }

    /// Set one of the vCPU's general purpose register.
    pub fn set_gpr_from_gpr_index(&mut self, index: GprIndex, val: usize) {
        self.regs.guest_regs.gprs.set_reg(index, val);
    }

    /// Advance guest pc by `instr_len` bytes
    pub fn advance_pc(&mut self, instr_len: usize) {
        self.regs.guest_regs.sepc += instr_len
    }

    /// Gets the vCPU's registers.
    pub fn regs(&mut self) -> &mut VmCpuRegisters {
        &mut self.regs
    }
}

impl RISCVVCpu {
    fn vmexit_handler(&mut self) -> AxResult<AxVCpuExitReason> {
        self.regs.trap_csrs.scause = scause::read().bits();
        self.regs.trap_csrs.stval = stval::read();
        self.regs.trap_csrs.htval = htval::read();
        self.regs.trap_csrs.htinst = htinst::read();

        let scause = scause::read();
        use scause::{Exception, Interrupt, Trap};

        debug!(
            "vmexit_handler: {:?}, sepc: {:#x}, stval: {:#x}",
            scause.cause(),
            self.regs.guest_regs.sepc,
            self.regs.trap_csrs.stval
        );

        match scause.cause() {
            Trap::Exception(Exception::VirtualSupervisorEnvCall) => {
                let a = self.regs.guest_regs.gprs.a_regs();
                let param = [a[0], a[1], a[2], a[3], a[4], a[5]];
                let extension_id = a[7];
                let function_id = a[6];

                

                match extension_id {
                    // Compatibility with Legacy Extensions.
                    time::EID_TIME => {
                        // panic!("sbi {}", time::EID_TIME);
                        // Clear guest timer interrupt
                        // unsafe {
                        //     hvip::clear_vstip();
                        // }

                        // info!("hvip:{:x?}",hvip::read());
                        // let callback = |_now: TimeValue| {
                        //     //TODO: add hvip to regs, and modify hvip in regs
                        //     // unsafe { hvip::set_vstip() };
                        //     // info!("call hvip:{:x?}",hvip::read());
                        //     self.assert_irq(scause::Interrupt::SupervisorTimer);
                        // };

                        // watch out!
                        self.advance_pc(4);
                        return Ok(AxVCpuExitReason::SbiCall(
                            SbiFunction::SetTimer { 
                                deadline: (param[0] * 100) as u64,
                                // callback: callback,
                            }
                        ));
                    }
                    spi::EID_SPI => {
                        let hart_mask = param[0] as u64;
                        let hart_mask_base = param[1] as u64;

                        // watch out!
                        self.advance_pc(4);
                        return Ok(AxVCpuExitReason::IPI { mask: hart_mask, base: hart_mask_base });
                    }
                    legacy::LEGACY_SET_TIMER..=legacy::LEGACY_SHUTDOWN => match extension_id {
                        legacy::LEGACY_SET_TIMER => {
                            // Clear guest timer interrupt
                            // unsafe {
                            //     hvip::clear_vstip();
                            // }
                            // info!("hvip:{:x?}",hvip::read());
                            // let callback = |_now: TimeValue| {
                            //     //TODO: add hvip to regs, and modify hvip in regs
                            //     unsafe { hvip::set_vstip() };
                            //     info!("call hvip:{:x?}",hvip::read());
                            // };

                            // let callback = Callback { vcpu: self };

                            unsafe {
                                PRINT = 2;
                            }

                            // watch out!
                            self.advance_pc(4);

                            return Ok(AxVCpuExitReason::SbiCall(
                                SbiFunction::SetTimer { 
                                    deadline: (param[0] * 100) as u64,
                                    // callback: callback,
                                }
                            ));


                            // return Ok(AxVCpuExitReason::SetTimer {
                            //     time: (param[0] * 100) as u64,
                            //     callback: callback,
                            // });
                        }
                        legacy::LEGACY_CONSOLE_PUTCHAR => {
                            sbi_call_legacy_1(legacy::LEGACY_CONSOLE_PUTCHAR, param[0]);
                        }
                        legacy::LEGACY_CONSOLE_GETCHAR => {
                            let c = sbi_call_legacy_0(legacy::LEGACY_CONSOLE_GETCHAR);
                            self.set_gpr_from_gpr_index(GprIndex::A0, c);
                        }
                        legacy::LEGACY_SHUTDOWN => {
                            // sbi_call_legacy_0(LEGACY_SHUTDOWN)
                            return Ok(AxVCpuExitReason::SystemDown);
                        }
                        _ => {
                            warn!(
                                "Unsupported SBI legacy extension id {:#x} function id {:#x}",
                                extension_id, function_id
                            );
                        }
                    },
                    // Handle HSM extension
                    hsm::EID_HSM => match function_id {
                        hsm::HART_START => {
                            let hartid = a[0];
                            let start_addr = a[1];
                            let opaque = a[2];
                            self.advance_pc(4);
                            return Ok(AxVCpuExitReason::CpuUp {
                                target_cpu: hartid as _,
                                entry_point: GuestPhysAddr::from(start_addr),
                                arg: opaque as _,
                            });
                        }
                        hsm::HART_STOP => {
                            return Ok(AxVCpuExitReason::CpuDown { _state: 0 });
                        }
                        hsm::HART_SUSPEND => {
                            // Todo: support these parameters.
                            let _suspend_type = a[0];
                            let _resume_addr = a[1];
                            let _opaque = a[2];
                            return Ok(AxVCpuExitReason::Halt);
                        }
                        _ => todo!(),
                    },
                    // Handle hypercall
                    EID_HVC => {
                        self.advance_pc(4);
                        return Ok(AxVCpuExitReason::Hypercall {
                            nr: function_id as _,
                            args: [
                                param[0] as _,
                                param[1] as _,
                                param[2] as _,
                                param[3] as _,
                                param[4] as _,
                                param[5] as _,
                            ],
                        });
                    }
                    // By default, forward the SBI call to the RustSBI implementation.
                    // See [`RISCVVCpuSbi`].
                    base::EID_BASE => {
                        let ret = self.sbi.handle_ecall(extension_id, function_id, param);
                        if ret.is_err() {
                            warn!(
                                "forward ecall eid {:#x} fid {:#x} param {:#x?} err {:#x} value {:#x}",
                                extension_id, function_id, param, ret.error, ret.value
                            );
                        }
                        self.set_gpr_from_gpr_index(GprIndex::A0, ret.error);
                        self.set_gpr_from_gpr_index(GprIndex::A1, ret.value);
                    }
                    _ => {
                        panic!("ecall eid {:#x} fid {:#x} param {:#x?}",extension_id, function_id, param)
                    }
                    // _ => {
                    //     let ret = self.sbi.handle_ecall(extension_id, function_id, param);
                    //     if ret.is_err() {
                    //         warn!(
                    //             "forward ecall eid {:#x} fid {:#x} param {:#x?} err {:#x} value {:#x}",
                    //             extension_id, function_id, param, ret.error, ret.value
                    //         );
                    //     }
                    //     self.set_gpr_from_gpr_index(GprIndex::A0, ret.error);
                    //     self.set_gpr_from_gpr_index(GprIndex::A1, ret.value);
                    // }
                };

                self.advance_pc(4);
                Ok(AxVCpuExitReason::Nothing)
            }
            Trap::Interrupt(Interrupt::SupervisorTimer) => {
                debug!("timer irq emulation");
                // Ok(AxVCpuExitReason::TimerIrq)
                // TODO: which vector?
                Ok(AxVCpuExitReason::ExternalInterrupt { vector: 10 })
            }
            Trap::Interrupt(Interrupt::SupervisorExternal) => {
                Ok(AxVCpuExitReason::ExternalInterrupt { vector: 0 })
            }
            Trap::Exception(Exception::LoadGuestPageFault)
            | Trap::Exception(Exception::StoreGuestPageFault) => {
                let fault_addr = self.regs.trap_csrs.htval << 2 | self.regs.trap_csrs.stval & 0x3;
                Ok(AxVCpuExitReason::NestedPageFault {
                    addr: GuestPhysAddr::from(fault_addr),
                    access_flags: MappingFlags::empty(),
                })
            }
            Trap::Exception(Exception::VirtualInstruction) => {
                let mut raw_inst = 0u32;
                // Safety: _fetch_guest_instruction internally detects and handles an invalid guest virtual
                // address in `pc' and will only write up to 4 bytes to `raw_inst`.
                let ret = unsafe { _fetch_guest_instruction(self.regs.guest_regs.sepc, &mut raw_inst) };
                if ret < 0 {
                    panic!("ret: {}", ret);
                }
                info!("raw inst: {:#x}x, {:#b}b", raw_inst, raw_inst);
                let decode_inst = riscv_decode::decode(raw_inst).unwrap();
                info!("decod_inst: {:#x?}", decode_inst);
                self.advance_pc(4);
                match decode_inst {
                    Instruction::Wfi => {
                        Ok(AxVCpuExitReason::Wfi)
                    }
                    _ => {
                        panic!("Unsupported instructions: {:#x?}", decode_inst);
                    }
                }
            }
            _ => {
                assert!(self.regs.trap_csrs.htval == htval::read());
                assert!(self.regs.trap_csrs.htinst == htinst::read());
                panic!(
                    "Unhandled trap: {:?}, sepc: {:#x}, stval: {:#x}, htval: {:#x}, htinst: {:#x}, ",
                    scause.cause(),
                    self.regs.guest_regs.sepc,
                    self.regs.trap_csrs.stval,
                    self.regs.trap_csrs.htval,
                    self.regs.trap_csrs.htinst,
                    
                );
            }
        }
    }
}

#[inline(always)]
fn sbi_call_legacy_0(eid: usize) -> usize {
    let error;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") eid,
            lateout("a0") error,
        );
    }
    error
}

#[inline(always)]
fn sbi_call_legacy_1(eid: usize, arg0: usize) -> usize {
    let error;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") eid,
            inlateout("a0") arg0 => error,
        );
    }
    error
}

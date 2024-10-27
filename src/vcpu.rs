use core::mem::size_of;

use axaddrspace::{GuestPhysAddr, HostPhysAddr, MappingFlags};
use axerrno::AxResult;
use axvcpu::AxArchVCpu;
use axvcpu::AxVCpuExitReason;
use riscv::addr::BitField;
use riscv::register::{hstatus, hvip, scause, sstatus, stval, htval, htinst, sie, stvec};
use sbi_rt::{pmu_counter_get_info, pmu_counter_stop};
use timer_list::TimeValue;

use crate::consts::traps::irq::TIMER_IRQ_NUM;
use crate::regs::*;
use crate::sbi::{BaseFunction, PmuFunction, RemoteFenceFunction, SbiMessage};

extern "C" {
    fn _run_guest(state: *mut VmCpuRegisters);
    fn _guest_exit();
    
}

/// The architecture dependent configuration of a `AxArchVCpu`.
#[derive(Clone, Copy, Debug, Default)]
pub struct VCpuConfig {}

#[derive(Default)]
/// A virtual CPU within a guest
pub struct RISCVVCpu {
    regs: VmCpuRegisters,
}

impl AxArchVCpu for RISCVVCpu {
    type CreateConfig = ();

    type SetupConfig = ();

    fn new(_config: Self::CreateConfig) -> AxResult<Self> {
        let mut regs = VmCpuRegisters::default();
        // Set hstatus
        let mut hstatus = hstatus::read();
        hstatus.set_spv(true);
        // Set SPVP bit in order to accessing VS-mode memory from HS-mode.
        hstatus.set_spvp(true);
        unsafe {
            hstatus.write();
        }
        regs.guest_regs.hstatus = hstatus.bits();

        // Set sstatus
        let mut sstatus = sstatus::read();
        sstatus.set_spp(sstatus::SPP::Supervisor);
        regs.guest_regs.sstatus = sstatus.bits();

        regs.guest_regs.gprs.set_reg(GprIndex::A0, 0);
        // TODO:from _config
        regs.guest_regs.gprs.set_reg(GprIndex::A1, 0x9000_0000);

        Ok(Self { regs })
    }

    fn setup(&mut self, _config: Self::SetupConfig) -> AxResult {
        Ok(())
    }

    fn set_entry(&mut self, entry: GuestPhysAddr) -> AxResult {
        let regs = &mut self.regs;
        regs.guest_regs.sepc = entry.as_usize();
        Ok(())
    }

    fn set_ept_root(&mut self, ept_root: HostPhysAddr) -> AxResult {
        self.regs.virtual_hs_csrs.hgatp = 8usize << 60 | usize::from(ept_root) >> 12;
        unsafe {
            core::arch::asm!(
                "csrw hgatp, {hgatp}",
                hgatp = in(reg) self.regs.virtual_hs_csrs.hgatp,
            );
            core::arch::riscv64::hfence_gvma_all();
        }
        Ok(())
    }

    fn run(&mut self) -> AxResult<AxVCpuExitReason> {
        let regs = &mut self.regs;
        unsafe {
            sstatus::clear_sie();
            sie::set_sext();
            sie::set_ssoft();
            sie::set_stimer();
        }

        // debug!("before run");
        unsafe {
            // Safe to run the guest as it only touches memory assigned to it by being owned
            // by its page table
            _run_guest(regs);
        }
        unsafe {
            sie::clear_sext();
            sie::clear_ssoft();
            sie::clear_stimer();
            sstatus::set_sie();
        }
        self.vmexit_handler()
    }

    fn bind(&mut self) -> AxResult {
        // unimplemented!()
        Ok(())
    }

    fn unbind(&mut self) -> AxResult {
        // unimplemented!()
        Ok(())
    }

    /// Set one of the vCPU's general purpose register.
    fn set_gpr(&mut self, index: usize, val: usize) {
        self.set_gpr_from_gpr_index(GprIndex::from_raw(index as u32).unwrap(), val);
    }
}

impl RISCVVCpu {
    /// Gets one of the vCPU's general purpose registers.
    pub fn get_gpr(&self, index: GprIndex) -> usize {
        self.regs.guest_regs.gprs.reg(index)
    }

    fn set_gpr_from_gpr_index(&mut self, index: GprIndex, val: usize) {
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

        // info!("trap: {:?}", scause.cause());

        use scause::{Exception, Interrupt, Trap};
        match scause.cause() {
            
            Trap::Interrupt(Interrupt::SupervisorTimer) => {
                // info!("timer irq emulation");
                // sbi_rt::set_timer(0);
                // unsafe {
                //     sie::set_stimer();
                // }
                // Ok(AxVCpuExitReason::Nothing)
                Ok(AxVCpuExitReason::TimerIrq)
            }
            Trap::Interrupt(Interrupt::SupervisorExternal) => {
                Ok(AxVCpuExitReason::ExternalInterrupt { vector: 0 })
            }
            Trap::Exception(Exception::VirtualSupervisorEnvCall) => {
                self.handle_sbi_msg()
            }
            Trap::Exception(Exception::LoadGuestPageFault)
            | Trap::Exception(Exception::StoreGuestPageFault) => {
                let fault_addr =
                    self.regs.trap_csrs.htval << 2 | self.regs.trap_csrs.stval & 0x3;
                Ok(AxVCpuExitReason::NestedPageFault {
                    addr: GuestPhysAddr::from(fault_addr),
                    access_flags: MappingFlags::empty(),
                })
            }
            _ => {
                panic!(
                    "Unhandled trap: {:?}, sepc: {:#x}, stval: {:#x}",
                    scause.cause(),
                    self.regs.guest_regs.sepc,
                    self.regs.trap_csrs.stval
                );
            }
            
        }
    }

    fn handle_sbi_msg(&mut self) -> AxResult<AxVCpuExitReason> {
        let sbi_msg = SbiMessage::from_regs(self.regs.guest_regs.gprs.a_regs()).ok();

        // info!("sbi: {:#?}", sbi_msg);

        if let Some(sbi_msg) = sbi_msg {
            match sbi_msg {
                SbiMessage::Base(base) => {
                    self.handle_base_function(base)?;
                }
                SbiMessage::GetChar => {
                    let c = sbi_rt::legacy::console_getchar();
                    self.set_gpr_from_gpr_index(GprIndex::A0, c);
                }
                SbiMessage::PutChar(c) => {
                    sbi_rt::legacy::console_putchar(c);
                }
                SbiMessage::SetTimer(timer) => {
                    // Clear guest timer interrupt
                    unsafe {
                        hvip::clear_vstip();
                    }
                    // info!("hvip:{:x?}",hvip::read());
                    let callback = |_now: TimeValue| {
                        //TODO: add hvip to regs, and modify hvip in regs
                        unsafe { hvip::set_vstip() };
                        // info!("call hvip:{:x?}",hvip::read());
                    };
                    // watch out!
                    self.advance_pc(4);
                    return Ok(AxVCpuExitReason::SetTimer { time: (timer*100) as u64, callback: callback });
                }
                SbiMessage::Reset(_) => {
                    sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::SystemFailure);
                }
                SbiMessage::RemoteFence(rfnc) => {
                    self.handle_rfnc_function(rfnc)?;
                }
                SbiMessage::PMU(pmu) => {
                    self.handle_pmu_function(pmu)?;
                }
                _ => {
                    todo!();
                },
            }
            self.advance_pc(4);
            Ok(AxVCpuExitReason::Nothing)
        } else {
            panic!(
                "Unhandled Trap: {:?}, sepc: {:#x}, stval: {:#x}",
                scause::read().cause(),
                self.regs.guest_regs.sepc,
                self.regs.trap_csrs.stval
            );
        }
    }

    fn handle_base_function(&mut self, base: BaseFunction) -> AxResult<()> {
        match base {
            BaseFunction::GetSepcificationVersion => {
                let version = sbi_rt::get_spec_version();
                self.set_gpr_from_gpr_index(GprIndex::A1, version.major() << 24 | version.minor());
                debug!(
                    "GetSepcificationVersion: {}",
                    version.major() << 24 | version.minor()
                );
            }
            BaseFunction::GetImplementationID => {
                let id = sbi_rt::get_sbi_impl_id();
                self.set_gpr_from_gpr_index(GprIndex::A1, id);
            }
            BaseFunction::GetImplementationVersion => {
                let impl_version = sbi_rt::get_sbi_impl_version();
                self.set_gpr_from_gpr_index(GprIndex::A1, impl_version);
            }
            BaseFunction::ProbeSbiExtension(extension) => {
                let extension = sbi_rt::probe_extension(extension as usize).raw;
                self.set_gpr_from_gpr_index(GprIndex::A1, extension);
            }
            BaseFunction::GetMachineVendorID => {
                let mvendorid = sbi_rt::get_mvendorid();
                self.set_gpr_from_gpr_index(GprIndex::A1, mvendorid);
            }
            BaseFunction::GetMachineArchitectureID => {
                let marchid = sbi_rt::get_marchid();
                self.set_gpr_from_gpr_index(GprIndex::A1, marchid);
            }
            BaseFunction::GetMachineImplementationID => {
                let mimpid = sbi_rt::get_mimpid();
                self.set_gpr_from_gpr_index(GprIndex::A1, mimpid);
            }
        }
        self.set_gpr_from_gpr_index(GprIndex::A0, 0);
        Ok(())
    }

    fn handle_rfnc_function(&mut self, rfnc: RemoteFenceFunction) -> AxResult<()> {
        self.set_gpr_from_gpr_index(GprIndex::A0, 0);
        match rfnc {
            RemoteFenceFunction::FenceI {
                hart_mask,
                hart_mask_base,
            } => {
                let sbi_ret = sbi_rt::remote_fence_i(hart_mask as usize, hart_mask_base as usize);
                self.set_gpr_from_gpr_index(GprIndex::A0, sbi_ret.error);
                self.set_gpr_from_gpr_index(GprIndex::A1, sbi_ret.value);
            }
            RemoteFenceFunction::RemoteSFenceVMA {
                hart_mask,
                hart_mask_base,
                start_addr,
                size,
            } => {
                let sbi_ret = sbi_rt::remote_sfence_vma(
                    hart_mask as usize,
                    hart_mask_base as usize,
                    start_addr as usize,
                    size as usize,
                );
                self.set_gpr_from_gpr_index(GprIndex::A0, sbi_ret.error);
                self.set_gpr_from_gpr_index(GprIndex::A1, sbi_ret.value);
            }
        }
        Ok(())
    }

    fn handle_pmu_function(&mut self, pmu: PmuFunction) -> AxResult<()> {
        self.set_gpr_from_gpr_index(GprIndex::A0, 0);
        match pmu {
            PmuFunction::GetNumCounters => {
                self.set_gpr_from_gpr_index(GprIndex::A1, sbi_rt::pmu_num_counters())
            }
            PmuFunction::GetCounterInfo(counter_index) => {
                let sbi_ret = pmu_counter_get_info(counter_index as usize);
                self.set_gpr_from_gpr_index(GprIndex::A0, sbi_ret.error);
                self.set_gpr_from_gpr_index(GprIndex::A1, sbi_ret.value);
            }
            PmuFunction::StopCounter {
                counter_index,
                counter_mask,
                stop_flags,
            } => {
                let sbi_ret = pmu_counter_stop(
                    counter_index as usize,
                    counter_mask as usize,
                    stop_flags as usize,
                );
                self.set_gpr_from_gpr_index(GprIndex::A0, sbi_ret.error);
                self.set_gpr_from_gpr_index(GprIndex::A1, sbi_ret.value);
            }
        }
        Ok(())
    }
}

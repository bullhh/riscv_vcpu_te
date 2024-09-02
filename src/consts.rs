pub mod traps {
    pub mod interrupt {
        pub const VIRTUAL_SUPERVISOR_SOFT: usize = 1 << 2;
        pub const VIRTUAL_SUPERVISOR_TIMER: usize = 1 << 6;
        pub const VIRTUAL_SUPERVISOR_EXTERNAL: usize = 1 << 10;
    }

    pub mod irq {
        /// `Interrupt` bit in `scause`
        pub const INTC_IRQ_BASE: usize = 1 << (usize::BITS - 1);

        /// Supervisor software interrupt in `scause`
        #[allow(unused)]
        pub const S_SOFT: usize = INTC_IRQ_BASE + 1;

        /// Supervisor timer interrupt in `scause`
        pub const S_TIMER: usize = INTC_IRQ_BASE + 5;

        /// Supervisor external interrupt in `scause`
        pub const S_EXT: usize = INTC_IRQ_BASE + 9;

        /// The maximum number of IRQs.
        pub const MAX_IRQ_COUNT: usize = 1024;

        /// The timer IRQ number (supervisor timer interrupt in `scause`).
        pub const TIMER_IRQ_NUM: usize = S_TIMER;
    }

    pub mod exception {
        pub const INST_ADDR_MISALIGN: usize = 1 << 0;
        pub const ILLEGAL_INST: usize = 1 << 2;
        pub const BREAKPOINT: usize = 1 << 3;
        pub const ENV_CALL_FROM_U_OR_VU: usize = 1 << 8;
        pub const INST_PAGE_FAULT: usize = 1 << 12;
        pub const LOAD_PAGE_FAULT: usize = 1 << 13;
        pub const STORE_PAGE_FAULT: usize = 1 << 15;
    }
}

pub mod timers {
    pub const TICKS_PER_SEC: u64 = 100;
    pub const NANOS_PER_SEC: u64 = 1_000_000_000;
    pub const PERIODIC_INTERVAL_NANOS: u64 = NANOS_PER_SEC / TICKS_PER_SEC;
    pub const TIMER_FREQUENCY: u64 = 10_000_000;
    pub const NANOS_PER_TICK: u64 = NANOS_PER_SEC / TIMER_FREQUENCY;
}

pub mod stack {
    pub const EXCEPTION_STACK_SIZE: usize = 8192;
}

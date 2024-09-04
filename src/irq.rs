//! Interrupt management.
use handler_table::HandlerTable;
use lazyinit::LazyInit;

use crate::consts::traps::irq::*;

/// The type if an IRQ handler.
pub type IrqHandler = handler_table::Handler;

static IRQ_HANDLER_TABLE: HandlerTable<MAX_IRQ_COUNT> = HandlerTable::new();
static TIMER_HANDLER: LazyInit<IrqHandler> = LazyInit::new();

/// Platform-independent IRQ dispatching.
#[allow(dead_code)]
pub(crate) fn dispatch_irq_common(irq_num: usize) {
    trace!("IRQ {}", irq_num);
    if !IRQ_HANDLER_TABLE.handle(irq_num) {
        warn!("Unhandled IRQ {}", irq_num);
    }
}

/// Platform-independent IRQ handler registration.
///
/// It also enables the IRQ if the registration succeeds. It returns `false` if
/// the registration failed.
#[allow(dead_code)]
pub(crate) fn register_handler_common(irq_num: usize, handler: IrqHandler) -> bool {
    if irq_num < MAX_IRQ_COUNT && IRQ_HANDLER_TABLE.register_handler(irq_num, handler) {
        return true;
    }
    warn!("register handler for IRQ {} failed", irq_num);
    false
}

pub fn handler_irq(irq_num: usize) -> bool {
    dispatch_irq(irq_num);
    true
}

macro_rules! with_cause {
    ($cause: expr, @TIMER => $timer_op: expr, @EXT => $ext_op: expr $(,)?) => {
        match $cause {
            S_TIMER => $timer_op,
            S_EXT => $ext_op,
            _ => panic!("invalid trap cause: {:#x}", $cause),
        }
    };
}

/// Registers an IRQ handler for the given IRQ.
///
/// It also enables the IRQ if the registration succeeds. It returns `false` if
/// the registration failed.
pub fn register_handler(scause: usize, handler: IrqHandler) -> bool {
    with_cause!(
        scause,
        @TIMER => if !TIMER_HANDLER.is_inited() {
            TIMER_HANDLER.init_once(handler);
            true
        } else {
            false
        },
        @EXT => register_handler_common(scause & !INTC_IRQ_BASE, handler),
    )
}

/// Dispatches the IRQ.
///
/// This function is called by the common interrupt handler. It looks
/// up in the IRQ handler table and calls the corresponding handler. If
/// necessary, it also acknowledges the interrupt controller after handling.
pub fn dispatch_irq(scause: usize) {
    with_cause!(
        scause,
        @TIMER => {
            trace!("IRQ: timer");
            TIMER_HANDLER();
        },
        @EXT => dispatch_irq_common(0), // TODO: get IRQ number from PLIC
    );
}

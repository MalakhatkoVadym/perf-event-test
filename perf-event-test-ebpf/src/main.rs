#![no_std]
#![no_main]

use aya_bpf::{
    helpers::bpf_get_smp_processor_id, macros::map, macros::perf_event, programs::PerfEventContext,
    BpfContext,
};
use perf_event_test_common::{ProcessInfo, MAIN_PERF_MAP, SECONDARY_PERF_MAP};

use aya_bpf::maps;

#[map]
static mut PID_EVENTS: maps::perf::PerfEventArray<ProcessInfo> = maps::PerfEventArray::new(0);

#[map]
static mut NO_PID_EVENTS: maps::perf::PerfEventArray<ProcessInfo> = maps::PerfEventArray::new(0);

#[perf_event]
pub fn perf_event_test(ctx: PerfEventContext) -> u32 {
    match try_perf_event_test(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_perf_event_test(ctx: PerfEventContext) -> Result<u32, u32> {
    let cpu = unsafe { bpf_get_smp_processor_id() };
    match ctx.pid() {
        0 => unsafe {
            PID_EVENTS.output(
                &ctx,
                &ProcessInfo {
                    perf_map_priority: MAIN_PERF_MAP,
                    pid: 0,
                    cpu,
                },
                0,
            );
        },
        pid => unsafe {
            PID_EVENTS.output(
                &ctx,
                &ProcessInfo {
                    perf_map_priority: SECONDARY_PERF_MAP,
                    pid,
                    cpu,
                },
                0,
            );
        },
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

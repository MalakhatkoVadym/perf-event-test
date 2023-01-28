#![no_std]

pub const MAIN_PERF_MAP: u32 = 0;
pub const SECONDARY_PERF_MAP: u32 = 1;

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct ProcessInfo {
    pub perf_map_priority: u32,
    pub pid: u32,
    pub cpu: u32,
}

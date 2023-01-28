use aya::maps::PerfEventArray;
use aya::programs::{perf_event, PerfEvent};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use bytes::BytesMut;
use perf_event_test_common::{ProcessInfo, MAIN_PERF_MAP, SECONDARY_PERF_MAP};
use tokio::runtime::Builder;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/perf-event-test"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/perf-event-test"
    ))?;

    let program: &mut PerfEvent = match bpf.program_mut("perf_event_test") {
        Some(program) => program.try_into()?,
        None => {
            eprintln!("Error loading program");
            return Ok(());
        }
    };
    program.load()?;
    // This will raise scheduled events on each CPU at 10 HZ, triggered by the kernel based
    // on clock ticks.
    for cpu in online_cpus()? {
        program.attach(
            perf_event::PerfTypeId::Software,
            perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
            perf_event::PerfEventScope::AllProcessesOneCpu { cpu },
            perf_event::SamplePolicy::Frequency(10),
        )?;
    }

    // PerfMaps for user events(pid) and kerner events(no pid)
    let mut pid_events = PerfEventArray::try_from(bpf.map_mut("PID_EVENTS")?)?;
    let mut no_pid_events = PerfEventArray::try_from(bpf.map_mut("NO_PID_EVENTS")?)?;

    // create a perf buffer for each CPU
    let mut perf_buffers = Vec::new();
    for cpu_id in online_cpus()? {
        // this perf buffer will receive events generated on the CPU with id cpu_id
        perf_buffers.push(pid_events.open(cpu_id, None)?);
        perf_buffers.push(no_pid_events.open(cpu_id, None)?);
    }

    // number of threads
    let cpus = num_cpus::get();

    // one thread pool is using all available threads
    let main_perf_rt = Builder::new_multi_thread()
        .worker_threads(cpus)
        .enable_time()
        .build()?;

    // one thread pool is using one thread
    let secondary_perf_rt = Builder::new_multi_thread()
        .worker_threads(1)
        .enable_time()
        .build()?;

    loop {
        for buffer in perf_buffers.iter_mut() {
            if buffer.readable() {
                let mut out_bufs = [BytesMut::with_capacity(1024)];

                buffer.read_events(&mut out_bufs)?;
                let (head, body, _tail) = unsafe {
                    match out_bufs.get(0) {
                        Some(out_buf) => out_buf.align_to::<ProcessInfo>(),
                        None => continue,
                    }
                };
                if !head.is_empty() {
                    eprintln!("Data not aligned");
                }

                let process_info = match body.get(0) {
                    Some(process_info) => *process_info,
                    None => continue,
                };

                // use different thread pools to handle different perf maps
                match process_info.perf_map_priority {
                    MAIN_PERF_MAP => {
                        main_perf_rt.handle().spawn(async move {
                            println!("Main perf map: {:?}", &process_info);
                        });
                    }
                    SECONDARY_PERF_MAP => {
                        secondary_perf_rt.handle().spawn(async move {
                            println!("Secondary perf map: {:?}", &process_info);
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    //Ok(())
}

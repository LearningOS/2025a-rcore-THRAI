//! Process management syscalls
use crate::{
    task::{exit_current_and_run_next, suspend_current_and_run_next},
    timer::get_time_us,
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("[kernel] Application exited with code {}", exit_code);
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// get time with second and microsecond
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    error!("kernel: sys_get_time");
    let us = get_time_us();
    unsafe {
        *ts = TimeVal {
            sec: us / 1_000_000,
            usec: us % 1_000_000,
        };
    }
    0
}


struct TraceReq;

impl TraceReq {
    const READ_BYTE_FROM_ID: usize = 0;
    const WRITE_TO_ID: usize = 1;
    const INQUIRE_CALL_TIME: usize = 2;
}

// TODO: implement the syscall
pub fn sys_trace(_trace_request: usize, _id: usize, _data: usize) -> isize {
    trace!("kernel: sys_trace");
    let u8_ptr = _id as *mut u8;

    match _trace_request {
        TraceReq::READ_BYTE_FROM_ID => {
            unsafe {u8_ptr.read_volatile() as isize}
        },
        TraceReq::WRITE_TO_ID => {
            let bytes = _data.to_le_bytes();
            unsafe {
                *u8_ptr = bytes[0];
            }
            0
        },
        TraceReq::INQUIRE_CALL_TIME => {
            use crate::task::TASK_MANAGER;
            let inner= TASK_MANAGER.inner.exclusive_access();
            let current_task = inner.current_task;
            let tasks = &inner.tasks;
            tasks[current_task].syscall_count[_id] as isize
        },
        _ => {
            -1
        }

    }
}

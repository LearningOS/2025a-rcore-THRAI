//! Process management syscalls
use crate::task::{TASK_MANAGER, change_program_brk, exit_current_and_run_next, suspend_current_and_run_next};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
use crate::mm::{VirtAddr};
use crate::timer::get_time_us;
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    use core::mem::size_of;

    let va = VirtAddr::from(_ts as usize);

    let us = get_time_us();
    let current_time = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };

    let translate_and_check = |vaddr: VirtAddr| -> Option<usize> {
        let tm_inner = TASK_MANAGER.inner.exclusive_access();
        let tcb = &tm_inner.tasks[tm_inner.current_task];
        let pte = tcb.memory_set.page_table.translate(vaddr.floor())?;

        if pte.is_user_writeable() {
            Some(pte.page_start_address() + vaddr.page_offset())
        } else {
            None
        }
    };

    if va.struct_cross_pages(size_of::<TimeVal>()) {
        if va.unaligned_with_size(size_of::<usize>()) {
            return -1;
        }

        let second_va = _ts as usize + size_of::<usize>();

        if let (Some(first_pa), Some(second_pa)) = (translate_and_check(va), translate_and_check(second_va.into())) {
            unsafe {
               let first_ptr = first_pa as *mut usize;
                *first_ptr = current_time.sec;

                let second_ptr = second_pa as *mut usize;
                *second_ptr = current_time.usec;
            }
            0
        } else {
            -1
        }
    } else if let Some(pa) = translate_and_check(va) {
        unsafe {
            let typed_ptr = pa as *mut TimeVal;
            *typed_ptr = current_time;
        }
        0
    } else {
        -1
    }
}

/// trace_req 0: return byte read from user space with va id
/// trace_req 1: write data to user space with va id
/// trace_req 2: return how much times syscall#id is called
pub fn sys_trace(trace_request: usize, _id: usize, _data: usize) -> isize {
    match trace_request {
        0 => {
            let va = VirtAddr::from(_id);
            let tm_inner = TASK_MANAGER.inner.exclusive_access();
            let tcb = &tm_inner.tasks[tm_inner.current_task];
            if let Some(pte) = tcb.memory_set.page_table.va_to_pte(va) {
                if !pte.is_valid() || !pte.is_user() {
                    return -1;
                }
                let pa = pte.page_start_address() + va.page_offset();
                unsafe { *(pa as *const u8) as isize }
            } else {
                -1
            }
        },
        1 => {
            let va = VirtAddr::from(_id);
            let tm_inner = TASK_MANAGER.inner.exclusive_access();
            let tcb = &tm_inner.tasks[tm_inner.current_task];
            if let Some(pte) = tcb.memory_set.page_table.va_to_pte(va) {
                if !pte.is_valid() || !pte.is_user() || !pte.writable() {
                    return -1;
                }
                let pa = pte.page_start_address() + va.page_offset();
                unsafe { *(pa as *mut u8) = _data as u8; }
                0
            } else {
                -1
            }
        },
        2 => {
            error!("trace request: count syscall#{} calls", _id);
            let tm_inner = TASK_MANAGER.inner.exclusive_access();
            let tcb = &tm_inner.tasks[tm_inner.current_task];
            *tcb.syscall_counts.get(&_id).unwrap_or(&0) as isize
        },
        _ => {
            error!("Invalid trace request: {}", trace_request);
            -1
        }
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, prot: usize) -> isize {
    const PAGE_SIZE: usize = 4096; // 2GB - 1, the maximum user space address
    if VirtAddr::from(start).page_offset() != 0 {
        return -1;
    }
    if (prot & !0x7) != 0 || (prot & 0x7) == 0 {
        return -1;
    }

    let len_aligned = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let area_end = start + len_aligned;

    use crate::mm::memory_set::MapPermission;
    let mut area_perm = MapPermission::U;
    if prot & 0x1 != 0 { area_perm |= MapPermission::R };
    if prot & 0x2 != 0 { area_perm |= MapPermission::W };
    if prot & 0x4 != 0 { area_perm |= MapPermission::X };

    // 3. 事务性临界区：保证检查与插入的绝对原子性
    let mut tm_inner = TASK_MANAGER.inner.exclusive_access();
    let current_task_id = tm_inner.current_task;
    let tcb = &mut tm_inner.tasks[current_task_id];

    // Check: 在持有锁的情况下验证空间兼容性
    if !tcb.memory_set.compatible_with(start.into(), area_end.into()) {
        return -1;
    }

    // Action: 状态合法，立即执行插入委托 (此时物理页分配 OOM 会通过 Result 传出)
    match tcb.memory_set.insert_framed_area(start.into(), area_end.into(), area_perm) {
        Ok(_) => 0,
        Err(_) => -1, // 物理内存不足，底层传递上来的错误
    }
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    if start % 4096 != 0 {
        return -1;
    }
    let mut tm_inner = TASK_MANAGER.inner.exclusive_access();
    let current_task_id = tm_inner.current_task;
    let tcb = &mut tm_inner.tasks[current_task_id];

    let len_aligned = (len + 4095) & !4095;
    let area_end = start + len_aligned;

    if tcb.memory_set.cross_areas(start.into(), area_end.into()) {
        return -1;
    }

    if !tcb.memory_set.perfectly_contains(start.into(), area_end.into()) {
        return -1;
    }

    tcb.memory_set.unmap_area(start.into(), area_end.into());
    0
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

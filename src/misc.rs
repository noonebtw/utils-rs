use std::time::{Duration, Instant};

pub fn wait_for<F, T>(
    timeout: Duration,
    step_len: Duration,
    callable: F,
) -> Option<T>
where
    F: Fn() -> Option<T>,
{
    let end = Instant::now() + timeout;

    while Instant::now() < end {
        if let Some(result) = callable() {
            return Some(result);
        }

        std::thread::sleep(step_len)
    }

    None
}

pub fn distance<I>(a: I, b: I) -> I
where
    I: Ord + Copy + num_traits::Zero + num_traits::PrimInt,
{
    use std::cmp::Ordering;

    match a.cmp(&b) {
        Ordering::Equal => I::zero(),
        Ordering::Less => b - a,
        Ordering::Greater => a - b,
    }
}

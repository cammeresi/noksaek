use std::hash::Hash;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::Semaphore;
use tokio::time::{Duration, MissedTickBehavior, interval};

pub struct MultiTokenBucket<T> {
    sems: Arc<DashMap<T, Arc<Semaphore>>>,
    capacity: usize,
    jh: tokio::task::JoinHandle<()>,
}

impl<T> MultiTokenBucket<T>
where
    T: Eq + Hash + Clone + Send + Sync + 'static,
{
    pub fn new(duration: Duration, capacity: usize) -> Self {
        let sems = Arc::new(DashMap::new());
        let sems2 = Arc::clone(&sems);
        let jh = tokio::spawn(Self::run(sems2, duration, capacity));
        Self { sems, capacity, jh }
    }

    async fn run(
        sems: Arc<DashMap<T, Arc<Semaphore>>>, duration: Duration,
        capacity: usize,
    ) {
        let mut interval = interval(duration);
        interval.set_missed_tick_behavior(MissedTickBehavior::Burst);

        // refill the tokens at the end of each interval
        loop {
            interval.tick().await;
            for sem in sems.iter() {
                if sem.available_permits() < capacity {
                    sem.add_permits(1);
                }
            }
        }
    }

    pub async fn acquire(&self, k: T) {
        let sem = {
            let entry = self.sems.entry(k);
            let sem =
                entry.or_insert_with(|| Semaphore::new(self.capacity).into());
            Arc::clone(&sem)
        };

        // deliberately leak and refill separately
        sem.acquire().await.unwrap().forget();
    }
}

impl<T> Drop for MultiTokenBucket<T> {
    fn drop(&mut self) {
        self.jh.abort();
    }
}

pub struct TokenBucket {
    inner: MultiTokenBucket<()>,
}

impl TokenBucket {
    pub fn new(duration: Duration, capacity: usize) -> Self {
        Self {
            inner: MultiTokenBucket::new(duration, capacity),
        }
    }

    pub async fn acquire(&self) {
        self.inner.acquire(()).await;
    }
}

#[cfg(test)]
mod test {
    use std::time::Instant;

    use tokio::time::timeout;

    use super::*;

    #[tokio::test]
    async fn exhaust() {
        const TOKENS: usize = 5;
        const PERIOD: Duration = Duration::from_secs(1);
        const TIMEOUT: Duration = PERIOD.checked_mul(5).unwrap();

        timeout(TIMEOUT, async {
            let b = TokenBucket::new(PERIOD, TOKENS);
            let start = Instant::now();
            for _ in 0..TOKENS + 2 {
                b.acquire().await;
            }
            assert!(start.elapsed() > PERIOD);
        })
        .await
        .unwrap();
    }
}

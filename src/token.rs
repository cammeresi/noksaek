use std::hash::Hash;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::Semaphore;
use tokio::time::{Duration, MissedTickBehavior, interval};

pub struct MultiTokenBucket<T> {
    sems: Arc<DashMap<T, Semaphore>>,
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
        sems: Arc<DashMap<T, Semaphore>>, duration: Duration, capacity: usize,
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
        let entry = self.sems.entry(k);
        let sem = entry.or_insert_with(|| Semaphore::new(self.capacity));

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

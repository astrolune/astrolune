// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Bounded workers retained across execution waves within one thread scope.

use std::{
    sync::mpsc::{Receiver, SyncSender, sync_channel},
    thread::{Builder, Scope, ScopedJoinHandle},
};

use crate::ExecutionError;

struct Worker<'scope, T, R> {
    requests: Option<SyncSender<T>>,
    results: Receiver<Result<R, ExecutionError>>,
    handle: Option<ScopedJoinHandle<'scope, ()>>,
}

pub(crate) struct ScopedWorkerPool<'scope, T, R> {
    workers: Vec<Worker<'scope, T, R>>,
    active: bool,
}

impl<'scope, T: Send + 'scope, R: Send + 'scope> ScopedWorkerPool<'scope, T, R> {
    pub(crate) fn new<'env, F>(
        scope: &'scope Scope<'scope, 'env>,
        count: usize,
        run: &'scope F,
    ) -> Result<Self, ExecutionError>
    where
        F: Fn(T) -> Result<R, ExecutionError> + Sync,
    {
        if count == 0 {
            return Err(ExecutionError::ResourceLimit);
        }
        let mut pool = Self {
            workers: Vec::new(),
            active: true,
        };
        pool.workers
            .try_reserve_exact(count)
            .map_err(|_| ExecutionError::ResourceLimit)?;
        for _ in 0..count {
            let (request_tx, request_rx) = sync_channel(1);
            let (result_tx, result_rx) = sync_channel(1);
            let handle = Builder::new()
                .spawn_scoped(scope, move || {
                    while let Ok(task) = request_rx.recv() {
                        if result_tx.send(run(task)).is_err() {
                            break;
                        }
                    }
                })
                .map_err(|_| ExecutionError::ResourceLimit)?;
            pool.workers.push(Worker {
                requests: Some(request_tx),
                results: result_rx,
                handle: Some(handle),
            });
        }
        Ok(pool)
    }

    /// Dispatch at most one task per worker into a reusable result buffer.
    ///
    /// The buffer is cleared before dispatch, preserves input order on success,
    /// and is empty on failure. Task or channel failures drain every dispatched
    /// response and shut down the pool. Further calls then return `Trap`. An
    /// oversized batch is rejected before dispatch and leaves the pool available
    /// for a valid batch.
    pub(crate) fn map_into(
        &mut self,
        tasks: impl ExactSizeIterator<Item = T>,
        outputs: &mut Vec<R>,
    ) -> Result<(), ExecutionError> {
        outputs.clear();
        if !self.active {
            return Err(ExecutionError::Trap);
        }
        if tasks.len() > self.workers.len() {
            return Err(ExecutionError::ResourceLimit);
        }
        outputs
            .try_reserve(tasks.len())
            .map_err(|_| ExecutionError::ResourceLimit)?;
        let mut dispatched = 0;
        let mut error = None;
        for (worker, task) in self.workers.iter().zip(tasks) {
            if worker
                .requests
                .as_ref()
                .is_none_or(|requests| requests.send(task).is_err())
            {
                error = Some(ExecutionError::Trap);
                break;
            }
            dispatched += 1;
        }
        for worker in self.workers.iter().take(dispatched) {
            match worker.results.recv() {
                Ok(Ok(output)) => outputs.push(output),
                Ok(Err(task_error)) => {
                    error.get_or_insert(task_error);
                }
                Err(_) => {
                    error.get_or_insert(ExecutionError::Trap);
                }
            }
        }
        if let Some(error) = error {
            outputs.clear();
            self.shutdown();
            Err(error)
        } else {
            Ok(())
        }
    }
}

impl<T, R> ScopedWorkerPool<'_, T, R> {
    fn shutdown(&mut self) {
        self.active = false;
        // Close every input first: otherwise an idle worker could block a join.
        for worker in &mut self.workers {
            worker.requests.take();
        }
        for worker in &mut self.workers {
            if let Some(handle) = worker.handle.take() {
                // Explicit joining also consumes panics, preventing the enclosing
                // thread scope from rethrowing a failure reported by map_into.
                let _ = handle.join();
            }
        }
    }
}

impl<T, R> Drop for ScopedWorkerPool<'_, T, R> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashSet,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    #[test]
    fn workers_are_bounded_and_reused_across_batches() {
        let starts = Mutex::new(HashSet::new());
        let run = |value| {
            let id = thread::current().id();
            starts.lock().unwrap().insert(id);
            Ok((value, id))
        };
        thread::scope(|scope| {
            let mut pool = ScopedWorkerPool::new(scope, 3, &run).unwrap();
            let mut outputs = Vec::new();
            pool.map_into([10, 20, 30].into_iter(), &mut outputs)
                .unwrap();
            let first = outputs.clone();
            for _ in 0..10 {
                pool.map_into([10, 20, 30].into_iter(), &mut outputs)
                    .unwrap();
                assert_eq!(outputs, first);
            }
            pool.map_into([10, 20].into_iter(), &mut outputs).unwrap();
            assert_eq!(outputs, first[..2]);
            pool.map_into([10].into_iter(), &mut outputs).unwrap();
            assert_eq!(outputs, first[..1]);
            pool.map_into(std::iter::empty(), &mut outputs).unwrap();
            assert_eq!(outputs, []);
            assert_eq!(starts.lock().unwrap().len(), 3);
        });
    }

    #[test]
    fn result_buffer_reuses_its_allocation_across_varying_batches() {
        let run = |value: usize| Ok(value * 2);
        thread::scope(|scope| {
            let mut pool = ScopedWorkerPool::new(scope, 3, &run).unwrap();
            let mut outputs = Vec::new();
            pool.map_into(1..4, &mut outputs).unwrap();
            assert_eq!(outputs, [2, 4, 6]);
            let capacity = outputs.capacity();
            let address = outputs.as_ptr();
            for count in [3, 1, 0, 2, 3] {
                pool.map_into(0..count, &mut outputs).unwrap();
                assert!(outputs.iter().copied().eq((0..count).map(|n| n * 2)));
                assert_eq!(outputs.capacity(), capacity);
                assert_eq!(outputs.as_ptr(), address);
            }
        });
    }

    #[test]
    fn oversized_batch_is_rejected_before_dispatch() {
        let calls = AtomicUsize::new(0);
        let run = |value| {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(value)
        };
        thread::scope(|scope| {
            let mut pool = ScopedWorkerPool::new(scope, 2, &run).unwrap();
            let mut outputs = vec![99];
            assert_eq!(
                pool.map_into([1, 2, 3].into_iter(), &mut outputs),
                Err(ExecutionError::ResourceLimit)
            );
            assert_eq!(outputs, []);
            assert_eq!(calls.load(Ordering::Relaxed), 0);
            pool.map_into([4, 5].into_iter(), &mut outputs).unwrap();
            assert_eq!(outputs, [4, 5]);
        });
    }

    #[test]
    fn task_error_drains_other_tasks_and_closes_pool() {
        let calls = AtomicUsize::new(0);
        let run = |value| {
            calls.fetch_add(1, Ordering::Relaxed);
            if value == 0 {
                Err(ExecutionError::ResourceLimit)
            } else {
                Ok(value)
            }
        };
        thread::scope(|scope| {
            let mut pool = ScopedWorkerPool::new(scope, 3, &run).unwrap();
            let mut outputs = vec![99];
            assert_eq!(
                pool.map_into([1, 0, 2].into_iter(), &mut outputs),
                Err(ExecutionError::ResourceLimit)
            );
            assert_eq!(outputs, []);
            assert_eq!(calls.load(Ordering::Relaxed), 3);
            assert!(pool.workers.iter().all(|worker| worker.handle.is_none()));
            outputs.push(99);
            assert_eq!(
                pool.map_into([3].into_iter(), &mut outputs),
                Err(ExecutionError::Trap)
            );
            assert_eq!(outputs, []);
        });
    }

    #[test]
    fn worker_panic_is_reported_without_escaping_thread_scope() {
        let calls = AtomicUsize::new(0);
        let run = |value| {
            calls.fetch_add(1, Ordering::Relaxed);
            assert_ne!(value, 0, "injected worker panic");
            Ok(value)
        };
        thread::scope(|scope| {
            let mut pool = ScopedWorkerPool::new(scope, 3, &run).unwrap();
            let mut outputs = vec![99];
            assert_eq!(
                pool.map_into([1, 0, 2].into_iter(), &mut outputs),
                Err(ExecutionError::Trap)
            );
            assert_eq!(outputs, []);
            assert_eq!(calls.load(Ordering::Relaxed), 3);
            assert!(pool.workers.iter().all(|worker| worker.handle.is_none()));
            assert_eq!(
                pool.map_into([3].into_iter(), &mut outputs),
                Err(ExecutionError::Trap)
            );
            assert_eq!(outputs, []);
        });
    }

    #[test]
    fn dropping_idle_workers_joins_them() {
        let run = |value: usize| Ok(value);
        thread::scope(|scope| {
            let pool = ScopedWorkerPool::new(scope, 3, &run).unwrap();
            drop(pool);
        });
    }

    #[test]
    fn zero_workers_are_rejected() {
        let run = |value: usize| Ok(value);
        thread::scope(|scope| {
            assert!(matches!(
                ScopedWorkerPool::new(scope, 0, &run),
                Err(ExecutionError::ResourceLimit)
            ));
        });
    }
}

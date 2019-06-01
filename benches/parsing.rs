#[macro_use]
extern crate criterion;
extern crate authorized_keys;

use authorized_keys::openssh::v2::KeysFile;
use std::str::FromStr;

use criterion::{black_box, Criterion};

const TEST_FILE: &str = include_str!("./test_keys.txt");

fn file_benchmark(c: &mut Criterion) {
    c.bench_function("parse benchmark file", |b| {
        b.iter(|| black_box(KeysFile::from_str(TEST_FILE).unwrap()))
    });
}

criterion_group!(benches, file_benchmark);
criterion_main!(benches);

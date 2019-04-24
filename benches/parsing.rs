#[macro_use]
extern crate criterion;
extern crate authorized_keys;

use authorized_keys::openssh::v2::{KeyAuthorization, KeysFile};
use std::str::FromStr;

use criterion::{black_box, Criterion};

const TEST_FILE: &str = include_str!("./test_keys.txt");
const TEST_LINE: &str = r#"no-agent-forwarding,command="echo \"Hello, world!\"" ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQABAAACAQC7hGnhOradeDBJ6ibZYXBtCti7UGmr9B0R9QjlQlAg35gW4bpBkT+Vij01jMP+dZMDZcLxfEOmmF9QFy2KMnxa42XXb8EeXovYiNvWeqAWfzQYKo7r2pgtwMLlN+ITRktE5tnEu7F5vgkSuDTyk0s2fvrKU5u88IID0k4aqBLp14oOAIur4Z+Zm4a545XOhJ7bEvM+nn/GGlzXATq7+Vd5DTcR/hn+Hi+YOuVT7BAmRsRTrCHT0xF9NiLZTw8AevUuUiCkoGQeyxU6p0D65emqWE9Wgu7xPR1B0DVV1t4zDwWULAvmFyLgwISL2WW7RwJfckTj3VCnSD6/4OEVFTqbISUM0FPNl2s9mme9yq3e5JR8ZpcxnLRybE4Gt+8ykiUgNcBxHsM2iJB5Ine512Vip5SiVZcRBTTY7bdy0wouvMvaL8UeNWql9q/9J+37T3+AYYHesr4zsdvD0NbVVtDKcgG3YhFIs6+B5rE99vYe8QnPzg2RiSxQz1yPaZFRbfMkAGS9G9mzbouxZSYfNOONlp7Xa0xnVqq9pAYDUmZf5JzpOvwmSuhTeQ+xJTxfZ7WtKpWnSdw5khx9N0i9ex4hNo8jcLLPBqwGztAkZbFHiFqGbA9qmkCMcuTpJkPYmviWFrdNoH+JiTJMFKVojGwGYtScEG5QwgdYBpxeeUhSjQ== this includes comments!"#;

fn file_benchmark(c: &mut Criterion) {
    c.bench_function("parse benchmark file", |b| {
        b.iter(|| black_box(KeysFile::from_str(TEST_FILE).unwrap()))
    });
}

fn line_benchmark(c: &mut Criterion) {
    c.bench_function("parse 5 identical lines", move |b| {
        b.iter(|| {
            for _i in 1..5 {
                black_box(
                    KeyAuthorization::from_str(black_box(TEST_LINE))
                        .expect("failed to parse valid line"),
                );
            }
        })
    });
}

criterion_group!(benches, file_benchmark, line_benchmark);
criterion_main!(benches);

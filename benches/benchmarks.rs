use criterion::{Bencher, Criterion};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rsa::{Padding, Rsa},
    sign::Signer,
};
use rand::{Rng, SeedableRng};
use serde_json::Map;

extern crate detached_jws;
#[macro_use]
extern crate criterion;
extern crate rand;

fn seriliaze_openssl_ps256_bench(b: &mut Bencher, &size: &usize) {
    let mut payload: Vec<u8> = Vec::with_capacity(size);
    fill(&mut payload);

    let keypair = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();

    let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
    signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();

    b.iter(|| {
        let _ = detached_jws::serialize(
            "PS256".to_owned(),
            Map::new(),
            &mut payload.as_slice(),
            &mut signer,
        )
        .unwrap();
    });
}

fn fill(v: &mut Vec<u8>) {
    let cap = v.capacity();
    let mut r = rand::rngs::SmallRng::from_entropy();
    while v.len() < cap {
        v.push(r.gen::<u8>());
    }
}

const BYTE_SIZES: [usize; 5] = [1, 3, 100, 3 * 1024, 10 * 1024 * 1024];

fn seriliaze_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("seriliaze-openssl");
    for size in BYTE_SIZES.iter() {
        group.bench_with_input(
            format!("PS256-payload-size-{}-bytes", size),
            size,
            seriliaze_openssl_ps256_bench,
        );
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = seriliaze_bench
}

criterion_main!(benches);

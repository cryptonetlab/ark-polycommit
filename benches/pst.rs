use ark_bls12_377::Bls12_377;
use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_poly::MultilinearExtension;
use ark_poly_commit::multilinear_pc::MultilinearPC;
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use ark_std::UniformRand;
use serde::Serialize;
use std::time::Instant;

type E = Bls12_377;
type Fr = <E as Pairing>::ScalarField;
#[derive(Default, Clone, Serialize)]
struct BenchmarkResults {
    power: usize,
    commit_time: u128,
    opening_time: u128,
    verification_time: u128,
    proof_size: usize,
    commiter_key_size: usize,
}

fn main() {
    let mut writer = csv::Writer::from_path("pst.csv").expect("unable to open csv writer");
    for &s in [4, 5, 20, 27].iter() {
        println!("Running for {} inputs", s);
        let mut rng = ark_std::test_rng();
        let mut br = BenchmarkResults::default();
        br.power = s;
        let nv = s;
        let poly = DenseMultilinearExtension::rand(nv, &mut rng);

        let uni_params = MultilinearPC::setup(nv, &mut rng);
        let (ck, vk) = MultilinearPC::<E>::trim(&uni_params, nv);
        let mut cks = Vec::<u8>::new();
        ck.serialize_with_mode(&mut cks, ark_serialize::Compress::Yes)
            .unwrap();
        br.commiter_key_size = cks.len();

        let point: Vec<_> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();

        let start = Instant::now();
        let com = MultilinearPC::commit(&ck, &poly);
        let duration = start.elapsed().as_millis();
        br.commit_time = duration;

        let start = Instant::now();
        let proof = MultilinearPC::open(&ck, &poly, &point);
        let duration = start.elapsed().as_millis();
        br.opening_time = duration;

        let value = poly.evaluate(&point).unwrap();

        let start = Instant::now();
        let result = MultilinearPC::check(&vk, &com, &point, value, &proof);
        assert!(result);
        let duration = start.elapsed().as_millis();
        br.verification_time = duration;

        let mut proof_serialised = Vec::<u8>::new();
        proof
            .serialize_with_mode(&mut proof_serialised, ark_serialize::Compress::Yes)
            .unwrap();
        br.proof_size = proof_serialised.len();

        writer
            .serialize(br)
            .expect("unable to write results to csv");
        writer.flush().expect("wasn't able to flush");
    }
}

use self::data_structures::{Commitment_G2, Proof_G1};

use super::timer::Timer;
use crate::multilinear_pc::data_structures::{
    Commitment, CommitterKey, Proof, UniversalParams, VerifierKey,
};
use ark_ec::msm::{FixedBase, VariableBaseMSM};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField};
use ark_ff::{One, Zero};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_std::collections::LinkedList;
use ark_std::iter::FromIterator;
use ark_std::marker::PhantomData;
use ark_std::ops::Mul;
use ark_std::rand::RngCore;
use ark_std::vec::Vec;
use ark_std::UniformRand;
use rayon::prelude::*;
use std::thread;
// use rayon::iter::ParallelIterator;
// use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator};
/// data structures used by multilinear extension commitment scheme
pub mod data_structures;

/// Polynomial Commitment Scheme on multilinear extensions.
pub struct MultilinearPC<E: PairingEngine> {
    _engine: PhantomData<E>,
}

impl<E: PairingEngine> MultilinearPC<E> {
    /// setup
    pub fn setup<R: RngCore>(num_vars: usize, rng: &mut R) -> UniversalParams<E> {
        assert!(num_vars > 0, "constant polynomial not supported");
        let g: E::G1Projective = E::G1Projective::rand(rng);
        let h: E::G2Projective = E::G2Projective::rand(rng);
        let g = g.into_affine();
        let h = h.into_affine();
        let mut powers_of_g = Vec::new();
        let mut powers_of_h = Vec::new();
        let t: Vec<_> = (0..num_vars).map(|_| E::Fr::rand(rng)).collect();
        let scalar_bits = E::Fr::MODULUS_BIT_SIZE as usize;

        let mut eq: LinkedList<DenseMultilinearExtension<E::Fr>> =
            LinkedList::from_iter(eq_extension(&t).into_iter());
        let mut eq_arr = LinkedList::new();
        let mut base = eq.pop_back().unwrap().evaluations;

        for i in (0..num_vars).rev() {
            eq_arr.push_front(remove_dummy_variable(&base, i));
            if i != 0 {
                let mul = eq.pop_back().unwrap().evaluations;
                base = base
                    .into_par_iter()
                    .zip(mul.into_par_iter())
                    .map(|(a, b)| a * &b)
                    .collect();
            }
        }

        let mut pp_powers = Vec::new();
        let mut total_scalars = 0;
        for i in 0..num_vars {
            let eq = eq_arr.pop_front().unwrap();
            let pp_k_powers = (0..(1 << (num_vars - i))).map(|x| eq[x]);
            pp_powers.extend(pp_k_powers);
            total_scalars += 1 << (num_vars - i);
        }
        let window_size = FixedBase::get_mul_window_size(total_scalars);
        let g_table = FixedBase::get_window_table(scalar_bits, window_size, g.into_projective());
        let h_table = FixedBase::get_window_table(scalar_bits, window_size, h.into_projective());

        let pp_g = E::G1Projective::batch_normalization_into_affine(&FixedBase::msm(
            scalar_bits,
            window_size,
            &g_table,
            &pp_powers,
        ));
        let pp_h = E::G2Projective::batch_normalization_into_affine(&FixedBase::msm(
            scalar_bits,
            window_size,
            &h_table,
            &pp_powers,
        ));
        let mut start = 0;
        for i in 0..num_vars {
            let size = 1 << (num_vars - i);
            let pp_k_g = (&pp_g[start..(start + size)]).to_vec();
            let pp_k_h = (&pp_h[start..(start + size)]).to_vec();
            powers_of_g.push(pp_k_g);
            powers_of_h.push(pp_k_h);
            start += size;
        }

        // uncomment to measure the time for calculating vp
        // let vp_generation_timer = start_timer!(|| "VP generation");
        let g_mask = {
            let window_size = FixedBase::get_mul_window_size(num_vars);
            let g_table =
                FixedBase::get_window_table(scalar_bits, window_size, g.into_projective());
            E::G1Projective::batch_normalization_into_affine(&FixedBase::msm(
                scalar_bits,
                window_size,
                &g_table,
                &t,
            ))
        };

        let h_mask = {
            let window_size = FixedBaseMSM::get_mul_window_size(num_vars);
            let h_table =
                FixedBaseMSM::get_window_table(scalar_bits, window_size, h.into_projective());
            E::G2Projective::batch_normalization_into_affine(&FixedBaseMSM::multi_scalar_mul(
                scalar_bits,
                window_size,
                &h_table,
                &t,
            ))
        };
        // end_timer!(vp_generation_timer);

        UniversalParams {
            num_vars,
            g,
            h,
            powers_of_g,
            powers_of_h,
            g_mask,
            h_mask,
        }
    }

    /// Trim the universal parameters to specialize the public parameters
    /// for multilinear polynomials to the given `supported_num_vars`, and returns committer key and verifier key.
    /// `supported_num_vars` should be in range `1..=params.num_vars`
    pub fn trim(
        params: &UniversalParams<E>,
        supported_num_vars: usize,
    ) -> (CommitterKey<E>, VerifierKey<E>) {
        assert!(supported_num_vars <= params.num_vars);
        let to_reduce = params.num_vars - supported_num_vars;
        let ck = CommitterKey {
            powers_of_h: (&params.powers_of_h[to_reduce..]).to_vec(),
            powers_of_g: (&params.powers_of_g[to_reduce..]).to_vec(),
            g: params.g,
            h: params.h,
            nv: supported_num_vars,
        };
        let vk = VerifierKey {
            nv: supported_num_vars,
            g: params.g,
            h: params.h,
            g_mask_random: (&params.g_mask[to_reduce..]).to_vec(),
            h_mask_random: (&params.h_mask[to_reduce..]).to_vec(),
        };
        (ck, vk)
    }

    /// commit
    pub fn commit(
        ck: &CommitterKey<E>,
        polynomial: &impl MultilinearExtension<E::Fr>,
    ) -> Commitment<E> {
        let nv = polynomial.num_vars();
        let scalars: Vec<_> = polynomial
            .to_evaluations()
            .into_par_iter()
            .map(|x| x.into_repr())
            .collect();
        let g_product =
            VariableBaseMSM::multi_scalar_mul(&ck.powers_of_g[0], scalars.as_slice()).into_affine();
        Commitment { nv, g_product }
    }

    /// commit the given polynomial using the G2 group as a basis
    /// That means the opening will be in G1.
    pub fn commit_g2(
        ck: &CommitterKey<E>,
        polynomial: &impl MultilinearExtension<E::Fr>,
    ) -> Commitment_G2<E> {
        let nv = polynomial.num_vars();
        let scalars: Vec<_> = polynomial
            .to_evaluations()
            .into_iter()
            .map(|x| x.into_repr())
            .collect();
        let h_product =
            VariableBaseMSM::multi_scalar_mul(&ck.powers_of_h[0], scalars.as_slice()).into_affine();
        Commitment_G2 { nv, h_product }
    }

    /// On input a polynomial `p` and a point `point`, outputs a proof for the same.
    pub fn open(
        ck: &CommitterKey<E>,
        polynomial: &impl MultilinearExtension<E::Fr>,
        point: &[E::Fr],
    ) -> Proof<E> {
        assert_eq!(polynomial.num_vars(), ck.nv, "Invalid size of polynomial");
        let nv = polynomial.num_vars();
        let mut r: Vec<Vec<E::Fr>> = (0..nv + 1).map(|_| Vec::new()).collect();
        let mut q: Vec<Vec<E::Fr>> = (0..nv + 1).map(|_| Vec::new()).collect();

        r[nv] = polynomial.to_evaluations();

        let mut proofs = Vec::new();
        for i in 0..nv {
            let k = nv - i;
            let point_at_k = point[i];
            q[k] = (0..(1 << (k - 1)))
                .into_par_iter()
                .map(|_| E::Fr::zero())
                .collect();
            r[k - 1] = (0..(1 << (k - 1)))
                .into_par_iter()
                .map(|_| E::Fr::zero())
                .collect();
            for b in 0..(1 << (k - 1)) {
                q[k][b] = r[k][(b << 1) + 1] - &r[k][b << 1];
                r[k - 1][b] = r[k][b << 1] * &(E::Fr::one() - &point_at_k)
                    + &(r[k][(b << 1) + 1] * &point_at_k);
            }
            let scalars: Vec<_> = (0..(1 << k))
                .into_par_iter()
                .map(|x| q[k][x >> 1].into_repr()) // fine
                .collect();

            let pi_h =
                <E::G2Projective as VariableBaseMSM>::msm_bigint(&ck.powers_of_h[i], &scalars)
                    .into_affine(); // no need to move outside and partition
            proofs.push(pi_h);
        }

        let proofs = thread_handles
            .into_par_iter()
            .map(|h| h.join().unwrap())
            .collect();

        Proof { proofs: proofs }
    }

    /// Create PST opening proof in G1 (with a commitment on G2)
    pub fn open_g1(
        ck: &CommitterKey<E>,
        polynomial: &impl MultilinearExtension<E::Fr>,
        point: &[E::Fr],
    ) -> Proof_G1<E> {
        assert_eq!(polynomial.num_vars(), ck.nv, "Invalid size of polynomial");
        let nv = polynomial.num_vars();
        let mut r: Vec<Vec<E::Fr>> = (0..nv + 1).map(|_| Vec::new()).collect();
        let mut q: Vec<Vec<E::Fr>> = (0..nv + 1).map(|_| Vec::new()).collect();

        r[nv] = polynomial.to_evaluations();

        let mut thread_handles = vec![];
        let proofs: Vec<_> = vec![E::G1Affine::zero(); nv];

        let mut i = 0;
        for mut p in proofs {
            let k = nv - i;
            let point_at_k = point[i];
            q[k] = (0..(1 << (k - 1))).map(|_| E::Fr::zero()).collect();
            r[k - 1] = (0..(1 << (k - 1))).map(|_| E::Fr::zero()).collect();
            for b in 0..(1 << (k - 1)) {
                q[k][b] = r[k][(b << 1) + 1] - &r[k][b << 1];
                r[k - 1][b] = r[k][b << 1] * &(E::Fr::one() - &point_at_k)
                    + &(r[k][(b << 1) + 1] * &point_at_k);
            }
            let scalars: Vec<_> = (0..(1 << k))
                .map(|x| q[k][x >> 1].into_repr()) // fine
                .collect();
            let pg = ck.powers_of_g[i].clone();
            thread_handles.push(thread::spawn(move || {
                p = VariableBaseMSM::multi_scalar_mul(&pg, &scalars).into_affine();
                p
            }));

            i = i + 1;
        }

        let proofs = thread_handles
            .into_iter()
            .map(|g| g.join().unwrap())
            .collect();

        Proof_G1 { proofs: proofs }
    }

    /// Verifies that `value` is the evaluation at `x` of the polynomial
    /// committed inside `comm`.
    pub fn check_2<'a>(
        vk: &VerifierKey<E>,
        commitment: &Commitment_G2<E>,
        point: &[E::Fr],
        value: E::Fr,
        proof: &Proof_G1<E>,
    ) -> bool {
        let left = E::pairing(
            vk.g,
            commitment.h_product.into_projective() - &vk.h.mul(value),
        );
        // println!("left is {:?}", left);

        let scalar_size = E::Fr::size_in_bits();
        let window_size = FixedBaseMSM::get_mul_window_size(vk.nv);

        let h_table =
            FixedBaseMSM::get_window_table(scalar_size, window_size, vk.h.into_projective());
        let h_mul: Vec<E::G2Projective> =
            FixedBaseMSM::multi_scalar_mul(scalar_size, window_size, &h_table, point);

        let pairing_rights: Vec<_> = (0..vk.nv)
            .into_iter()
            .map(|i| vk.h_mask_random[i].into_projective() - &h_mul[i])
            .collect();
        let pairing_rights: Vec<E::G2Affine> =
            E::G2Projective::batch_normalization_into_affine(&pairing_rights);
        let pairing_rights: Vec<E::G2Prepared> = pairing_rights
            .into_iter()
            .map(|x| E::G2Prepared::from(x))
            .collect();

        let pairing_lefts: Vec<E::G1Prepared> = proof
            .proofs
            .iter()
            .map(|x| E::G1Prepared::from(*x))
            .collect();

        let pairings: Vec<_> = pairing_lefts
            .into_iter()
            .zip(pairing_rights.into_iter())
            .collect();
        let right = E::product_of_pairings(pairings.iter());
        // println!("right is {:?}", right);

        left == right
    }

    /// Check a polynomial opening proof in G2 and commitment on G1
    pub fn check<'a>(
        vk: &VerifierKey<E>,
        commitment: &Commitment<E>,
        point: &[E::Fr],
        value: E::Fr,
        proof: &Proof<E>,
    ) -> bool {
        let left = E::pairing(
            commitment.g_product.into_projective() - &vk.g.mul(value),
            vk.h,
        );

        let scalar_size = E::Fr::MODULUS_BIT_SIZE as usize;
        let window_size = FixedBase::get_mul_window_size(vk.nv);

        let g_table = FixedBase::get_window_table(scalar_size, window_size, vk.g.into_projective());
        let g_mul: Vec<E::G1Projective> = FixedBase::msm(scalar_size, window_size, &g_table, point);

        let pairing_lefts: Vec<_> = (0..vk.nv)
            .into_par_iter()
            .map(|i| vk.g_mask_random[i].into_projective() - &g_mul[i])
            .collect();
        let pairing_lefts: Vec<E::G1Affine> =
            E::G1Projective::batch_normalization_into_affine(&pairing_lefts);
        let pairing_lefts: Vec<E::G1Prepared> = pairing_lefts
            .into_par_iter()
            .map(|x| E::G1Prepared::from(x))
            .collect();

        let pairing_rights: Vec<E::G2Prepared> = proof
            .proofs
            .par_iter()
            .map(|x| E::G2Prepared::from(*x))
            .collect();

        let pairings: Vec<_> = pairing_lefts
            .into_par_iter()
            .zip(pairing_rights.into_par_iter())
            .collect();
        let right = E::product_of_pairings(pairings.iter());
        left == right
    }
}

/// fix first `pad` variables of `poly` represented in evaluation form to zero
fn remove_dummy_variable<F: Field>(poly: &[F], pad: usize) -> Vec<F> {
    if pad == 0 {
        return poly.to_vec();
    }
    if !poly.len().is_power_of_two() {
        panic!("Size of polynomial should be power of two. ")
    }
    let nv = ark_std::log2(poly.len()) as usize - pad;
    let table: Vec<_> = (0..(1 << nv)).map(|x| poly[x << pad]).collect();
    table
}

/// generate eq(t,x), a product of multilinear polynomials with fixed t.
/// eq(a,b) is takes extensions of a,b in {0,1}^num_vars such that if a and b in {0,1}^num_vars are equal
/// then this polynomial evaluates to 1.
pub fn eq_extension<F: Field>(t: &[F]) -> Vec<DenseMultilinearExtension<F>> {
    let dim = t.len();
    let mut result = Vec::new();
    for i in 0..dim {
        let mut poly = Vec::with_capacity(1 << dim);
        for x in 0..(1 << dim) {
            let xi = if x >> i & 1 == 1 { F::one() } else { F::zero() };
            let ti = t[i];
            let ti_xi = ti * xi;
            poly.push(ti_xi + ti_xi - xi - ti + F::one());
        }
        result.push(DenseMultilinearExtension::from_evaluations_vec(dim, poly));
    }

    result
}

#[cfg(test)]
mod tests {
    use crate::multilinear_pc::data_structures::UniversalParams;
    use crate::multilinear_pc::MultilinearPC;
    use ark_bls12_381::Bls12_381;
    use ark_ec::PairingEngine;
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension, SparseMultilinearExtension};
    use ark_std::rand::RngCore;
    use ark_std::vec::Vec;
    use ark_std::{test_rng, UniformRand};
    type E = Bls12_381;
    type Fr = <E as PairingEngine>::Fr;

    fn test_polynomial<R: RngCore>(
        uni_params: &UniversalParams<E>,
        poly: &impl MultilinearExtension<Fr>,
        rng: &mut R,
    ) {
        let nv = poly.num_vars();
        assert_ne!(nv, 0);
        let (ck, vk) = MultilinearPC::<E>::trim(&uni_params, nv);
        let point: Vec<_> = (0..nv).map(|_| Fr::rand(rng)).collect();
        let com = MultilinearPC::commit(&ck, poly);
        let proof = MultilinearPC::open(&ck, poly, &point);

        let value = poly.evaluate(&point).unwrap();
        let result = MultilinearPC::check(&vk, &com, &point, value, &proof);
        assert!(result);
    }

    fn test_polynomial_g2<R: RngCore>(
        uni_params: &UniversalParams<E>,
        poly: &impl MultilinearExtension<Fr>,
        rng: &mut R,
    ) {
        let nv = poly.num_vars();
        assert_ne!(nv, 0);
        let (ck, vk) = MultilinearPC::<E>::trim(&uni_params, nv);
        let point: Vec<_> = (0..nv).map(|_| Fr::rand(rng)).collect();
        let com = MultilinearPC::commit_g2(&ck, poly);
        let proof = MultilinearPC::open_g1(&ck, poly, &point);

        let value = poly.evaluate(&point).unwrap();
        let result = MultilinearPC::check_2(&vk, &com, &point, value, &proof);
        assert!(result);
    }

    #[test]
    fn test() {
        let mut rng = test_rng();

        // normal polynomials
        let uni_params = MultilinearPC::setup(2, &mut rng);

        let poly1 = DenseMultilinearExtension::rand(2, &mut rng);
        test_polynomial_g2(&uni_params, &poly1, &mut rng);
    }

    #[test]
    fn setup_commit_verify_correct_polynomials() {
        let mut rng = test_rng();

        // normal polynomials
        let uni_params = MultilinearPC::setup(10, &mut rng);

        let poly1 = DenseMultilinearExtension::rand(8, &mut rng);
        test_polynomial(&uni_params, &poly1, &mut rng);

        let poly2 = SparseMultilinearExtension::rand_with_config(9, 1 << 5, &mut rng);
        test_polynomial(&uni_params, &poly2, &mut rng);

        // single-variate polynomials

        let poly3 = DenseMultilinearExtension::rand(1, &mut rng);
        test_polynomial(&uni_params, &poly3, &mut rng);

        let poly4 = SparseMultilinearExtension::rand_with_config(1, 1 << 1, &mut rng);
        test_polynomial(&uni_params, &poly4, &mut rng);
    }

    #[test]
    #[should_panic]
    fn setup_commit_verify_constant_polynomial() {
        let mut rng = test_rng();

        // normal polynomials
        MultilinearPC::<E>::setup(0, &mut rng);
    }

    #[test]
    fn setup_commit_verify_incorrect_polynomial_should_return_false() {
        let mut rng = test_rng();
        let nv = 8;
        let uni_params = MultilinearPC::setup(nv, &mut rng);
        let poly = DenseMultilinearExtension::rand(nv, &mut rng);
        let nv = uni_params.num_vars;
        let (ck, vk) = MultilinearPC::<E>::trim(&uni_params, nv);
        let point: Vec<_> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
        let com = MultilinearPC::commit(&ck, &poly);
        let proof = MultilinearPC::open(&ck, &poly, &point);

        let value = poly.evaluate(&point).unwrap();
        let result = MultilinearPC::check(&vk, &com, &point, value + &(1u16.into()), &proof);
        assert!(!result);
    }
}

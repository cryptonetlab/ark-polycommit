use crate::{BTreeMap, Vec};
use crate::{
    PCCommitterKey, PCPreparedVerifierKey, PCRandomness, PCUniversalParams, PCVerifierKey,
};
use ark_ec::pairing::Pairing;
use ark_poly::DenseMVPolynomial;
use ark_std::{
    io::{Read, Write},
    marker::PhantomData,
    ops::{Add, AddAssign, Index},
};

use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};
use ark_std::rand::RngCore;

/// `UniversalParams` are the universal parameters for the MarlinPST13 scheme.
#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Debug(bound = ""))]
pub struct UniversalParams<E, P>
where
    E: Pairing,
    P: DenseMVPolynomial<E::ScalarField>,
    P::Point: Index<usize, Output = E::ScalarField>,
{
    /// Contains group elements corresponding to all possible monomials with
    /// `num_vars` and maximum degree `max_degree` evaluated at `\beta`
    pub powers_of_g: BTreeMap<P::Term, E::G1Affine>,
    /// `\gamma` times the generater of G1
    pub gamma_g: E::G1Affine,
    /// Group elements of the form `{ \beta_i^j \gamma G }`, where `i` ranges
    /// from 0 to `num_vars-1` and `j` ranges from `1` to `max_degree+1`.
    pub powers_of_gamma_g: Vec<Vec<E::G1Affine>>,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// Group elements of the form `{ \beta_i H }`, where `i` ranges from 0 to `num_vars-1`
    pub beta_h: Vec<E::G2Affine>,
    /// The generator of G2, prepared for use in pairings.
    #[derivative(Debug = "ignore")]
    pub prepared_h: E::G2Prepared,
    /// Group elements of the form `{ \beta_i H }`, where `i` ranges from 0 to `num_vars-1`,
    /// prepared for use in pairings
    #[derivative(Debug = "ignore")]
    pub prepared_beta_h: Vec<E::G2Prepared>,
    /// The number of variables `self` is initialized for
    pub num_vars: usize,
    /// The maximum degree supported by `self`
    pub max_degree: usize,
}

impl<E, P> Valid for UniversalParams<E, P>
where
    E: Pairing,
    P: DenseMVPolynomial<E::ScalarField>,
    P::Point: Index<usize, Output = E::ScalarField>,
{
    fn check(&self) -> Result<(), SerializationError> {
        if self.powers_of_g.len() != (self.max_degree + 1) * self.num_vars {
            return Err(SerializationError::InvalidData);
        }

        if self.beta_h.len() != self.num_vars {
            return Err(SerializationError::InvalidData);
        }

        if self.prepared_beta_h.len() != self.num_vars {
            return Err(SerializationError::InvalidData);
        }
        Ok(())
    }
}

impl<E, P> CanonicalSerialize for UniversalParams<E, P>
where
    E: Pairing,
    P: DenseMVPolynomial<E::ScalarField>,
    P::Point: Index<usize, Output = E::ScalarField>,
{
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.powers_of_g
            .serialize_with_mode(&mut writer, compress)?;
        self.gamma_g.serialize_with_mode(&mut writer, compress)?;
        self.powers_of_gamma_g
            .serialize_with_mode(&mut writer, compress)?;
        self.h.serialize_with_mode(&mut writer, compress)?;
        self.beta_h.serialize_with_mode(&mut writer, compress)?;
        self.num_vars.serialize_with_mode(&mut writer, compress)?;
        self.max_degree.serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.powers_of_g.serialized_size(compress)
            + self.gamma_g.serialized_size(compress)
            + self.powers_of_gamma_g.serialized_size(compress)
            + self.h.serialized_size(compress)
            + self.beta_h.serialized_size(compress)
            + self.num_vars.serialized_size(compress)
            + self.max_degree.serialized_size(compress)
    }

    fn serialize_uncompressed<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        Self::serialize_with_mode(self, &mut writer, Compress::No)
    }

    fn uncompressed_size(&self) -> usize {
        Self::serialized_size(self, Compress::No)
    }
    fn compressed_size(&self) -> usize {
        Self::serialized_size(self, Compress::Yes)
    }
}

impl<E, P> CanonicalDeserialize for UniversalParams<E, P>
where
    E: Pairing,
    P: DenseMVPolynomial<E::ScalarField>,
    P::Point: Index<usize, Output = E::ScalarField>,
{
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let powers_of_g = BTreeMap::<P::Term, E::G1Affine>::deserialize_with_mode(
            &mut reader,
            compress,
            validate,
        )?;
        let gamma_g = E::G1Affine::deserialize_with_mode(&mut reader, compress, validate)?;
        let powers_of_gamma_g =
            Vec::<Vec<E::G1Affine>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let h = E::G2Affine::deserialize_with_mode(&mut reader, compress, validate)?;
        let beta_h = Vec::<E::G2Affine>::deserialize_with_mode(&mut reader, compress, validate)?;
        let num_vars = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let max_degree = usize::deserialize_with_mode(&mut reader, compress, validate)?;

        let prepared_beta_h = beta_h.iter().map(|x| x.clone().into()).collect();
        Ok(Self {
            powers_of_g,
            gamma_g,
            powers_of_gamma_g,
            h,
            beta_h,
            prepared_h: h.into(),
            prepared_beta_h,
            num_vars,
            max_degree,
        })
    }

    fn deserialize_uncompressed<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Self::deserialize_with_mode(reader, Compress::No, Validate::Yes)
    }
    fn deserialize_uncompressed_unchecked<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Self::deserialize_with_mode(reader, Compress::No, Validate::No)
    }
    fn deserialize_compressed_unchecked<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Self::deserialize_with_mode(reader, Compress::Yes, Validate::No)
    }
    fn deserialize_compressed<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Self::deserialize_with_mode(
            reader,
            ark_serialize::Compress::Yes,
            ark_serialize::Validate::Yes,
        )
    }
}

impl<E, P> PCUniversalParams for UniversalParams<E, P>
where
    E: Pairing,
    P: DenseMVPolynomial<E::ScalarField>,
    P::Point: Index<usize, Output = E::ScalarField>,
{
    fn max_degree(&self) -> usize {
        self.max_degree
    }
}

/// `CommitterKey` is used to commit to and create evaluation proofs for a given
/// polynomial.
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(Hash(bound = ""), Clone(bound = ""), Debug(bound = ""))]
pub struct CommitterKey<E, P>
where
    E: Pairing,
    P: DenseMVPolynomial<E::ScalarField>,
    P::Point: Index<usize, Output = E::ScalarField>,
{
    /// Contains group elements corresponding to all possible monomials with
    /// `num_vars` and maximum degree `supported_degree` evaluated at `\beta`
    pub powers_of_g: BTreeMap<P::Term, E::G1Affine>,
    /// `\gamma` times the generater of G1
    pub gamma_g: E::G1Affine,
    /// Group elements of the form `{ \beta_i^j \gamma G }`, where `i` ranges
    /// from 0 to `num_vars-1` and `j` ranges from `1` to `supported_degree+1`.
    pub powers_of_gamma_g: Vec<Vec<E::G1Affine>>,
    /// The number of variables `self` is initialized for
    pub num_vars: usize,
    /// The maximum degree supported by the trimmed parameters that `self` is
    /// a part of
    pub supported_degree: usize,
    /// The maximum degree supported by the `UniversalParams` `self` was derived
    /// from.
    pub max_degree: usize,
}

impl<E, P> PCCommitterKey for CommitterKey<E, P>
where
    E: Pairing,
    P: DenseMVPolynomial<E::ScalarField>,
    P::Point: Index<usize, Output = E::ScalarField>,
{
    fn max_degree(&self) -> usize {
        self.max_degree
    }

    fn supported_degree(&self) -> usize {
        self.supported_degree
    }
}

/// `VerifierKey` is used to check evaluation proofs for a given commitment.
#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Debug(bound = ""))]
pub struct VerifierKey<E: Pairing> {
    /// The generator of G1.
    pub g: E::G1Affine,
    /// The generator of G1 that is used for making a commitment hiding.
    pub gamma_g: E::G1Affine,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// `\beta_i` times the above generator of G2 where `i` ranges from 0 to `num_vars-1`
    pub beta_h: Vec<E::G2Affine>,
    /// The generator of G2, prepared for use in pairings.
    #[derivative(Debug = "ignore")]
    pub prepared_h: E::G2Prepared,
    /// `\beta_i` times the above generator of G2 where `i` ranges from 0 to `num_vars-1`,
    /// prepared for use in pairings
    #[derivative(Debug = "ignore")]
    pub prepared_beta_h: Vec<E::G2Prepared>,
    /// The number of variables `self` is initialized for
    pub num_vars: usize,
    /// The maximum degree supported by the trimmed parameters that `self` is
    /// a part of.
    pub supported_degree: usize,
    /// The maximum degree supported by the `UniversalParams` `self` was derived
    /// from.
    pub max_degree: usize,
}
impl<E: Pairing> Valid for VerifierKey<E> {
    fn check(&self) -> Result<(), SerializationError> {
        if self.num_vars == 0 {
            return Err(SerializationError::InvalidData);
        }
        if self.supported_degree == 0 {
            return Err(SerializationError::InvalidData);
        }
        if self.max_degree == 0 {
            return Err(SerializationError::InvalidData);
        }
        if self.beta_h.len() != self.num_vars {
            return Err(SerializationError::InvalidData);
        }
        if self.prepared_beta_h.len() != self.num_vars {
            return Err(SerializationError::InvalidData);
        }
        Ok(())
    }
}
impl<E: Pairing> CanonicalSerialize for VerifierKey<E> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.g.serialize_with_mode(&mut writer, compress)?;
        self.gamma_g.serialize_with_mode(&mut writer, compress)?;
        self.h.serialize_with_mode(&mut writer, compress)?;
        self.beta_h.serialize_with_mode(&mut writer, compress)?;
        self.num_vars.serialize_with_mode(&mut writer, compress)?;
        self.supported_degree
            .serialize_with_mode(&mut writer, compress)?;
        self.max_degree.serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.g.serialized_size(compress)
            + self.gamma_g.serialized_size(compress)
            + self.h.serialized_size(compress)
            + self.beta_h.serialized_size(compress)
            + self.num_vars.serialized_size(compress)
            + self.supported_degree.serialized_size(compress)
            + self.max_degree.serialized_size(compress)
    }

    fn serialize_uncompressed<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        Self::serialize_with_mode(&self, writer, Compress::No)
    }
    fn serialize_compressed<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        Self::serialize_with_mode(&self, writer, Compress::Yes)
    }

    fn uncompressed_size(&self) -> usize {
        Self::serialized_size(&self, Compress::No)
    }
    fn compressed_size(&self) -> usize {
        Self::serialized_size(&self, Compress::Yes)
    }
}

impl<E: Pairing> CanonicalDeserialize for VerifierKey<E> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let g = E::G1Affine::deserialize_with_mode(&mut reader, compress, validate)?;
        let gamma_g = E::G1Affine::deserialize_with_mode(&mut reader, compress, validate)?;
        let h = E::G2Affine::deserialize_with_mode(&mut reader, compress, validate)?;
        let beta_h = Vec::<E::G2Affine>::deserialize_with_mode(&mut reader, compress, validate)?;
        let num_vars = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let supported_degree = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let max_degree = usize::deserialize_with_mode(&mut reader, compress, validate)?;

        let prepared_beta_h = beta_h.iter().map(|x| x.clone().into()).collect();
        Ok(Self {
            g,
            gamma_g,
            h,
            beta_h,
            prepared_h: h.into(),
            prepared_beta_h,
            num_vars,
            supported_degree,
            max_degree,
        })
    }
    fn deserialize_compressed<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Self::deserialize_with_mode(reader, Compress::Yes, Validate::Yes)
    }
    fn deserialize_compressed_unchecked<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Self::deserialize_with_mode(reader, Compress::Yes, Validate::No)
    }
    fn deserialize_uncompressed<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Self::deserialize_with_mode(reader, Compress::No, Validate::Yes)
    }
    fn deserialize_uncompressed_unchecked<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Self::deserialize_with_mode(reader, Compress::No, Validate::No)
    }
}

impl<E: Pairing> PCVerifierKey for VerifierKey<E> {
    fn max_degree(&self) -> usize {
        self.max_degree
    }

    fn supported_degree(&self) -> usize {
        self.supported_degree
    }
}

/// Nothing to do to prepare this verifier key (for now).
pub type PreparedVerifierKey<E> = VerifierKey<E>;

impl<E: Pairing> PCPreparedVerifierKey<VerifierKey<E>> for PreparedVerifierKey<E> {
    /// prepare `PreparedVerifierKey` from `VerifierKey`
    fn prepare(vk: &VerifierKey<E>) -> Self {
        vk.clone()
    }
}

/// `Randomness` hides the polynomial inside a commitment`.
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Hash(bound = ""),
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
pub struct Randomness<E, P>
where
    E: Pairing,
    P: DenseMVPolynomial<E::ScalarField>,
    P::Point: Index<usize, Output = E::ScalarField>,
{
    /// A multivariate polynomial where each monomial is univariate with random coefficient
    pub blinding_polynomial: P,
    _engine: PhantomData<E>,
}

impl<E, P> Randomness<E, P>
where
    E: Pairing,
    P: DenseMVPolynomial<E::ScalarField>,
    P::Point: Index<usize, Output = E::ScalarField>,
{
    /// Does `self` provide any hiding properties to the corresponding commitment?
    /// `self.is_hiding() == true` only if the underlying polynomial is non-zero.
    #[inline]
    pub fn is_hiding(&self) -> bool {
        !self.blinding_polynomial.is_zero()
    }

    /// What is the degree of the hiding polynomial for a given hiding bound?
    #[inline]
    pub fn calculate_hiding_polynomial_degree(hiding_bound: usize) -> usize {
        hiding_bound + 1
    }
}

impl<E, P> PCRandomness for Randomness<E, P>
where
    E: Pairing,
    P: DenseMVPolynomial<E::ScalarField>,
    P::Point: Index<usize, Output = E::ScalarField>,
{
    fn empty() -> Self {
        Self {
            blinding_polynomial: P::zero(),
            _engine: PhantomData,
        }
    }

    fn rand<R: RngCore>(
        hiding_bound: usize,
        _: bool,
        num_vars: Option<usize>,
        rng: &mut R,
    ) -> Self {
        let hiding_poly_degree = Self::calculate_hiding_polynomial_degree(hiding_bound);
        Randomness {
            blinding_polynomial: P::rand(hiding_poly_degree, num_vars.unwrap(), rng),
            _engine: PhantomData,
        }
    }
}

impl<'a, E: Pairing, P: DenseMVPolynomial<E::ScalarField>> Add<&'a Randomness<E, P>>
    for Randomness<E, P>
where
    E: Pairing,
    P: DenseMVPolynomial<E::ScalarField>,
    P::Point: Index<usize, Output = E::ScalarField>,
{
    type Output = Self;

    #[inline]
    fn add(mut self, other: &'a Self) -> Self {
        self.blinding_polynomial += &other.blinding_polynomial;
        self
    }
}

impl<'a, E, P> Add<(E::ScalarField, &'a Randomness<E, P>)> for Randomness<E, P>
where
    E: Pairing,
    P: DenseMVPolynomial<E::ScalarField>,
    P::Point: Index<usize, Output = E::ScalarField>,
{
    type Output = Self;

    #[inline]
    fn add(mut self, other: (E::ScalarField, &'a Randomness<E, P>)) -> Self {
        self += other;
        self
    }
}

impl<'a, E, P> AddAssign<&'a Randomness<E, P>> for Randomness<E, P>
where
    E: Pairing,
    P: DenseMVPolynomial<E::ScalarField>,
    P::Point: Index<usize, Output = E::ScalarField>,
{
    #[inline]
    fn add_assign(&mut self, other: &'a Self) {
        self.blinding_polynomial += &other.blinding_polynomial;
    }
}

impl<'a, E, P> AddAssign<(E::ScalarField, &'a Randomness<E, P>)> for Randomness<E, P>
where
    E: Pairing,
    P: DenseMVPolynomial<E::ScalarField>,
    P::Point: Index<usize, Output = E::ScalarField>,
{
    #[inline]
    fn add_assign(&mut self, (f, other): (E::ScalarField, &'a Randomness<E, P>)) {
        self.blinding_polynomial += (f, &other.blinding_polynomial);
    }
}

/// `Proof` is an evaluation proof that is output by `KZG10::open`.
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
pub struct Proof<E: Pairing> {
    /// Commitments to the witness polynomials
    pub w: Vec<E::G1Affine>,
    /// Evaluation of the random polynomial at the point for which
    /// the evaluation proof was produced.
    pub random_v: Option<E::ScalarField>,
}

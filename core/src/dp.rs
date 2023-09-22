#[cfg(feature = "test-util")]
use crate::test_util::dummy_vdaf::Vdaf;
use anyhow::anyhow;
use derivative::Derivative;
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::traits::Fixed;
#[cfg(feature = "fpvec_bounded_l2")]
use prio::flp::{
    gadgets::{ParallelSumGadget, PolyEval},
    types::fixedpoint_l2::{compatible_float::CompatibleFloat, FixedPointBoundedL2VecSum},
};
use prio::{
    dp::{
        distributions::ZCdpDiscreteGaussian, DifferentialPrivacyBudget,
        DifferentialPrivacyDistribution, DifferentialPrivacyStrategy, DpError,
    },
    field::{Field128, Field64},
    flp::{
        gadgets::{Mul, ParallelSum, ParallelSumMultithreaded},
        TypeWithNoise,
    },
    vdaf::{xof::XofShake128, AggregatorWithNoise},
};
use serde::{Deserialize, Serialize};

// strategy enum for dispatch

#[derive(Debug, Derivative, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DpStrategyInstance {
    NoDifferentialPrivacy,
    ZCdpDiscreteGaussian(ZCdpDiscreteGaussian),
}

impl DpStrategyInstance {}

// identity strategy

pub struct NoBudget;
impl DifferentialPrivacyBudget for NoBudget {}

pub struct NoDistribution;
impl DifferentialPrivacyDistribution for NoDistribution {}

#[derive(Debug, Derivative, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NoDifferentialPrivacy;
impl DifferentialPrivacyStrategy for NoDifferentialPrivacy {
    type Budget = NoBudget;
    type Distribution = NoDistribution;
    type Sensitivity = ();
    fn from_budget(_b: NoBudget) -> Self {
        NoDifferentialPrivacy
    }
    fn create_distribution(&self, _s: Self::Sensitivity) -> Result<Self::Distribution, DpError> {
        Ok(NoDistribution)
    }
}

// converting strategy enum into strategy types

impl TryFrom<DpStrategyInstance> for NoDifferentialPrivacy {
    type Error = anyhow::Error;
    fn try_from(value: DpStrategyInstance) -> Result<Self, Self::Error> {
        match value {
            DpStrategyInstance::NoDifferentialPrivacy => Ok(NoDifferentialPrivacy),
            DpStrategyInstance::ZCdpDiscreteGaussian(_) => Err(anyhow!(
                "Attempted to use ZCdp instance for NoDp strategy".to_string(),
            )),
        }
    }
}

impl TryFrom<DpStrategyInstance> for ZCdpDiscreteGaussian {
    type Error = anyhow::Error;
    fn try_from(value: DpStrategyInstance) -> Result<Self, Self::Error> {
        match value {
            DpStrategyInstance::ZCdpDiscreteGaussian(s) => Ok(s),
            DpStrategyInstance::NoDifferentialPrivacy => Err(anyhow!(
                "Attempted to use NoDp instance for ZCdp strategy".to_string(),
            )),
        }
    }
}

// identity strategy implementations for vdafs from janus
#[cfg(feature = "test-util")]
impl AggregatorWithNoise<0, 16, NoDifferentialPrivacy> for Vdaf {
    fn add_noise_to_agg_share(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_param: &Self::AggregationParam,
        _agg_share: &mut Self::AggregateShare,
        _num_measurements: usize,
    ) -> Result<(), prio::vdaf::VdafError> {
        Ok(())
    }
}

// identity strategy implementations for vdafs from libprio
impl TypeWithNoise<NoDifferentialPrivacy> for prio::flp::types::Sum<Field128> {
    fn add_noise_to_result(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_result: &mut [Self::Field],
        _num_measurements: usize,
    ) -> Result<(), prio::flp::FlpError> {
        Ok(())
    }
}
impl TypeWithNoise<NoDifferentialPrivacy> for prio::flp::types::Count<Field64> {
    fn add_noise_to_result(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_result: &mut [Self::Field],
        _num_measurements: usize,
    ) -> Result<(), prio::flp::FlpError> {
        Ok(())
    }
}
impl TypeWithNoise<NoDifferentialPrivacy>
    for prio::flp::types::Histogram<Field128, ParallelSum<Field128, Mul<Field128>>>
{
    fn add_noise_to_result(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_result: &mut [Self::Field],
        _num_measurements: usize,
    ) -> Result<(), prio::flp::FlpError> {
        Ok(())
    }
}
impl TypeWithNoise<NoDifferentialPrivacy>
    for prio::flp::types::SumVec<Field128, ParallelSumMultithreaded<Field128, Mul<Field128>>>
{
    fn add_noise_to_result(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_result: &mut [Self::Field],
        _num_measurements: usize,
    ) -> Result<(), prio::flp::FlpError> {
        Ok(())
    }
}

#[cfg(feature = "fpvec_bounded_l2")]
impl<T, SPoly, SBlindPoly> TypeWithNoise<NoDifferentialPrivacy>
    for FixedPointBoundedL2VecSum<T, SPoly, SBlindPoly>
where
    T: Fixed + CompatibleFloat,
    SPoly: ParallelSumGadget<Field128, PolyEval<Field128>> + Eq + Clone + 'static,
    SBlindPoly: ParallelSumGadget<Field128, Mul<Field128>> + Eq + Clone + 'static,
{
    fn add_noise_to_result(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_result: &mut [Self::Field],
        _num_measurements: usize,
    ) -> Result<(), prio::flp::FlpError> {
        Ok(())
    }
}

impl AggregatorWithNoise<16, 16, NoDifferentialPrivacy>
    for prio::vdaf::poplar1::Poplar1<XofShake128, 16>
{
    fn add_noise_to_agg_share(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_param: &Self::AggregationParam,
        _agg_share: &mut Self::AggregateShare,
        _num_measurements: usize,
    ) -> Result<(), prio::vdaf::VdafError> {
        Ok(())
    }
}

// macro to use in dispatch

/// If the first argument is non-empty, the `true` body is emitted,
/// otherwise, the `false` body is emitted. Useful to generate different
/// code in case an optional argument of an outer macro was given.
#[macro_export]
macro_rules! if_ident_exists {
    ($token:ident, true => $body1:tt, false => $body2:tt) => {
        $body1
    };
    (, true => $body1:tt, false => $body2:tt) => {
        $body2
    };
}

pub mod operator;
pub mod operator_committee;
pub mod impls;


macro_rules! define_mod {
    ($name: ident, $mod: path) => {
        pub mod $name {
            use $mod as committee_variant;

            use crate::validation::operator_committee::*;

            pub type OperatorCommittee = GenericOperatorCommittee<
                committee_variant::OperatorCommittee,
            >;
        }
    };
}

#[cfg(feature = "fake_committee")]
define_mod!(fake_committee_implementations, crate::validation::impls::fake::types);

#[cfg(feature = "fake_committee")]
pub use fake_committee_implementations::*;

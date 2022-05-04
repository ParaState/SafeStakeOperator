//pub mod bls;
pub mod define;
//pub mod threshold;
pub mod generic_threshold;
pub mod impls;

macro_rules! define_mod {
    ($name: ident, $mod: path) => {
        pub mod $name {
            use $mod as bls_variant;

            use crate::crypto::generic_threshold::*;

            pub type ThresholdSignature = GenericThresholdSignature<
                bls_variant::ThresholdSignature,
            >;
        }
    };
}

define_mod!(blst_threshold_implementations, crate::crypto::impls::blst::types);
pub use blst_threshold_implementations::*;

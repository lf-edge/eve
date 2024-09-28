/// Everything in this module is internal API and may change at any time.
#[doc(hidden)]
pub mod __internal {
    /// A reexport of core to allow our macros to be generic to std vs core.
    pub use ::core as core_export;

    /// A reexport of serde so our users don't have to also have a serde dependency.
    #[cfg(feature = "serde")]
    pub use serde2 as serde;

    /// Reexports of internal types
    pub use crate::{
        repr::{ArrayRepr, EnumSetTypeRepr},
        traits::EnumSetTypePrivate,
    };
}

/// Creates a EnumSet literal, which can be used in const contexts.
///
/// The syntax used is `enum_set!(Type::A | Type::B | Type::C)`. Each variant must be of the same
/// type, or an error will occur at compile-time.
///
/// This macro accepts trailing `|`s to allow easier use in other macros.
///
/// # Examples
///
/// ```rust
/// # use enumset::*;
/// # #[derive(EnumSetType, Debug)] enum Enum { A, B, C }
/// const CONST_SET: EnumSet<Enum> = enum_set!(Enum::A | Enum::B);
/// assert_eq!(CONST_SET, Enum::A | Enum::B);
/// ```
///
/// This macro is strongly typed. For example, the following will not compile:
///
/// ```compile_fail
/// # use enumset::*;
/// # #[derive(EnumSetType, Debug)] enum Enum { A, B, C }
/// # #[derive(EnumSetType, Debug)] enum Enum2 { A, B, C }
/// let type_error = enum_set!(Enum::A | Enum2::B);
/// ```
#[macro_export]
macro_rules! enum_set {
    ($(|)*) => {
        EnumSet::empty()
    };
    ($value:path $(|)*) => {
        {
            #[allow(deprecated)] let value = $value.__impl_enumset_internal__const_only();
            value
        }
    };
    ($value:path | $($rest:path)|* $(|)*) => {
        $crate::enum_set_union!($value, $($rest,)*)
    };
}

/// Computes the union of multiple enums or constants enumset at compile time.
///
/// The syntax used is `enum_set_union!(ENUM_A, ENUM_B, ENUM_C)`, computing the equivalent of
/// `ENUM_A | ENUM_B | ENUM_C` at compile time. Each variant must be of the same type, or an error
/// will occur at compile-time.
///
/// # Examples
///
/// ```rust
/// # use enumset::*;
/// # #[derive(EnumSetType, Debug)] enum Enum { A, B, C }
/// const CONST_SET: EnumSet<Enum> = enum_set_union!(Enum::A, Enum::B);
/// assert_eq!(CONST_SET, Enum::A | Enum::B);
/// ```
#[macro_export]
macro_rules! enum_set_union {
    ($value:path $(,)?) => {
        $crate::enum_set!($value)
    };
    ($value:path, $($rest:path),* $(,)?) => {
        {
            #[allow(deprecated)] let helper = $value.__impl_enumset_internal__const_helper();
            #[allow(deprecated)] let value = $value.__impl_enumset_internal__const_only();
            $(#[allow(deprecated)] let value = {
                let new = $rest.__impl_enumset_internal__const_only();
                helper.const_union(value, new)
            };)*
            value
        }
    };
}

/// Computes the intersection of multiple enums or constants enumset at compile time.
///
/// The syntax used is `enum_set_intersection!(ENUM_A, ENUM_B, ENUM_C)`, computing the equivalent
/// of `ENUM_A & ENUM_B & ENUM_C` at compile time. Each variant must be of the same type, or an
/// error will occur at compile-time.
///
/// # Examples
///
/// ```rust
/// # use enumset::*;
/// # #[derive(EnumSetType, Debug)] enum Enum { A, B, C, D }
/// const SET_A: EnumSet<Enum> = enum_set!(Enum::A | Enum::B);
/// const SET_B: EnumSet<Enum> = enum_set!(Enum::B | Enum::C);
/// const CONST_SET: EnumSet<Enum> = enum_set_intersection!(SET_A, SET_B);
/// assert_eq!(CONST_SET, Enum::B);
/// ```
#[macro_export]
macro_rules! enum_set_intersection {
    ($value:path $(,)?) => {
        $crate::enum_set!($value)
    };
    ($value:path, $($rest:path),* $(,)?) => {
        {
            #[allow(deprecated)] let helper = $value.__impl_enumset_internal__const_helper();
            #[allow(deprecated)] let value = $value.__impl_enumset_internal__const_only();
            $(#[allow(deprecated)] let value = {
                let new = $rest.__impl_enumset_internal__const_only();
                helper.const_intersection(value, new)
            };)*
            value
        }
    };
}

/// Computes the complement of an enums or constants enumset at compile time.
///
/// # Examples
///
/// ```rust
/// # use enumset::*;
/// # #[derive(EnumSetType, Debug)] enum Enum { A, B, C, D }
/// const SET: EnumSet<Enum> = enum_set!(Enum::B | Enum::C);
/// const CONST_SET: EnumSet<Enum> = enum_set_complement!(SET);
/// assert_eq!(CONST_SET, Enum::A | Enum::D);
/// ```
#[macro_export]
macro_rules! enum_set_complement {
    ($value:path $(,)?) => {{
        #[allow(deprecated)]
        let helper = $value.__impl_enumset_internal__const_helper();
        #[allow(deprecated)]
        let value = $value.__impl_enumset_internal__const_only();
        helper.const_complement(value)
    }};
}

/// Computes the difference of multiple enums or constants enumset at compile time.
///
/// The syntax used is `enum_set_difference!(ENUM_A, ENUM_B, ENUM_C)`, computing the equivalent
/// of `ENUM_A - ENUM_B - ENUM_C` at compile time. Each variant must be of the same type, or an
/// error will occur at compile-time.
///
/// # Examples
///
/// ```rust
/// # use enumset::*;
/// # #[derive(EnumSetType, Debug)] enum Enum { A, B, C, D }
/// const SET_A: EnumSet<Enum> = enum_set!(Enum::A | Enum::B | Enum::D);
/// const SET_B: EnumSet<Enum> = enum_set!(Enum::B | Enum::C);
/// const CONST_SET: EnumSet<Enum> = enum_set_symmetric_difference!(SET_A, SET_B);
/// assert_eq!(CONST_SET, Enum::A | Enum::C | Enum::D);
/// ```
#[macro_export]
macro_rules! enum_set_difference {
    ($value:path $(,)?) => {
        $crate::enum_set!($value)
    };
    ($value:path, $($rest:path),* $(,)?) => {
        {
            #[allow(deprecated)] let helper = $value.__impl_enumset_internal__const_helper();
            #[allow(deprecated)] let value = $value.__impl_enumset_internal__const_only();
            $(#[allow(deprecated)] let value = {
                let new = $rest.__impl_enumset_internal__const_only();
                helper.const_intersection(value, helper.const_complement(new))
            };)*
            value
        }
    };
}

/// Computes the symmetric difference of multiple enums or constants enumset at compile time.
///
/// The syntax used is `enum_set_symmetric_difference!(ENUM_A, ENUM_B, ENUM_C)`, computing the
/// equivalent of `ENUM_A ^ ENUM_B ^ ENUM_C` at compile time. Each variant must be of the same
/// type, or an error will occur at compile-time.
///
/// # Examples
///
/// ```rust
/// # use enumset::*;
/// # #[derive(EnumSetType, Debug)] enum Enum { A, B, C, D }
/// const SET_A: EnumSet<Enum> = EnumSet::all();
/// const SET_B: EnumSet<Enum> = enum_set!(Enum::B | Enum::C);
/// const CONST_SET: EnumSet<Enum> = enum_set_difference!(SET_A, SET_B);
/// assert_eq!(CONST_SET, Enum::A | Enum::D);
/// ```
#[macro_export]
macro_rules! enum_set_symmetric_difference {
    ($value:path $(,)?) => {
        $crate::enum_set!($value)
    };
    ($value:path, $($rest:path),* $(,)?) => {
        {
            #[allow(deprecated)] let helper = $value.__impl_enumset_internal__const_helper();
            #[allow(deprecated)] let value = $value.__impl_enumset_internal__const_only();
            $(#[allow(deprecated)] let value = {
                let new = $rest.__impl_enumset_internal__const_only();
                helper.const_symmetric_difference(value, new)
            };)*
            value
        }
    };
}

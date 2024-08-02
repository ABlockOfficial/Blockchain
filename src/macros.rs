/// Generate an enum to be used as an error type.
///
/// This will automatically generate the enum, but also implement `Display` with given format
/// strings and optionally indicate the source error for errors which wrap another error.
///
/// Example usage:
/// ```ignore
/// make_error_type!(pub enum MyError {
///     Unknown; "Unknown error",
///     IncorrectLength(length: usize); "Incorrect length {length}, expected 123",
///     InvalidHexData(source: hex::FromHexError); "Cannot convert hex string: {source}"; source,
/// });
/// ```
macro_rules! make_error_type {
    (@fmt_source) => { None };
    (@fmt_source $sourcen:expr) => { Some($sourcen) };

    (
        $( #[$attr:meta] )*
        $vis:vis enum $name:ident {
            $( $(
                #[$tattr:meta] )*
                $tname:ident
                    $(( $( $( #[$t_tuple_arg_attr:meta] )* $t_tuple_arg_name:ident : $t_tuple_arg_ty:ty),+ $(,)? ))?
                    $({ $( $( #[$t_struct_arg_attr:meta] )* $t_struct_arg_name:ident : $t_struct_arg_ty:ty),+ $(,)? })?
                ; $tmsg:literal $(( $($tmsgarg:expr),* ))?
                $( ; $sourcen:expr )?
            ),+ $(,)?
        }
    ) => {
        $( #[$attr] )*
        #[derive(::std::fmt::Debug)]
        $vis enum $name {
            $(
                $( #[$tattr] )*
                $tname
                    $(( $( $( #[$t_tuple_arg_attr] )* $t_tuple_arg_ty),+ ))?
                    $({ $( $( #[$t_struct_arg_attr] )* $t_struct_arg_name : $t_struct_arg_ty),+ })?
            ),+
        }

        impl std::error::Error for $name {
            #[allow(unused_variables)]
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    $(
                        Self::$tname
                            $(( $($t_tuple_arg_name),+ ))?
                            $({ $($t_struct_arg_name),+ })?
                        =>
                        make_error_type!(@fmt_source $($sourcen)?)
                    ),+
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, _f: &mut std::fmt::Formatter) -> std::fmt::Result {
                match self {
                    $(
                        Self::$tname
                            $(( $($t_tuple_arg_name),+ ))?
                            $({ $($t_struct_arg_name),+ })?
                        =>
                        write!(_f, $tmsg $($(, $tmsgarg)*)? )
                    ),+
                }
            }
        }
    };
}

/// Generate an enum where each variant represents a unique named value.
///
/// This will automatically generate the enum, but also implement the following traits:
/// * `ToName` and `FromName` with the variant names
/// * `Display` with the variant names
///
/// Additionally, a constant array containing every enum variant will be generated with the
/// given name and visibility.
///
/// Example usage:
/// ```ignore
/// make_trivial_enum!(pub enum MyError {
///     Hello,
///     World,
/// }
/// all_variants=pub(crate) ALL_VARIANTS);
/// ```
macro_rules! make_trivial_enum {
    (
        @impl_toname_fromname_display
        $ename:ident {
            $( $vname:ident ),+
        }
        $all_variants_vis:vis $all_variants:ident
    ) => {
        impl $ename {
            #[allow(unused)]
            $all_variants_vis const $all_variants : &'static [Self] =
                &[ $( Self::$vname ),+ ];
        }

        impl crate::utils::ToName for $ename {
            fn to_name(&self) -> &'static str {
                match self {
                    $( Self::$vname => stringify!($vname) ),+
                }
            }
        }

        impl crate::utils::FromName for $ename {
            const ALL_NAMES: &'static [&'static str] = &[ $( stringify!($vname) ),+ ];

            fn from_name(name: &str) -> Result<Self, &str> {
                match name {
                    $( stringify!($vname) => Ok(Self::$vname), )+
                    _ => Err(name),
                }
            }
        }

        impl std::fmt::Display for $ename {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str(crate::utils::ToName::to_name(self))
            }
        }
    };

    (
        $( #[$eattr:meta] )*
        $evis:vis enum $ename:ident {
            $(
                $( #[$vattr:meta] )*
                $vname:ident,
            )+
        }
        all_variants=$all_variants_vis:vis $all_variants:ident
    ) => {
        $( #[$eattr] )*
        $evis enum $ename {
            $( $( #[$vattr] )* $vname ),+
        }

        make_trivial_enum!(
            @impl_toname_fromname_display $ename {
                $( $vname ),+
            }
            $all_variants_vis $all_variants);
    };
}

/// Generate an enum where each variant simply wraps a numeric ordinal number.
///
/// This will automatically generate the enum, but also implement the following traits:
/// * `ToOrdinal` and `FromOrdinal` with the given ordinal numbers
/// * `ToName` and `FromName` with the variant names
/// * `Display` with the variant names
///
/// Additionally, a constant array containing every enum variant will be generated with the
/// given name and visibility.
///
/// Example usage:
/// ```ignore
/// make_ordinal_enum!(pub enum MyError {
///     Hello = 2,
///     World = 3,
/// }
/// all_variants=pub(crate) ALL_VARIANTS);
/// ```
macro_rules! make_ordinal_enum {
    (
        $( #[$eattr:meta] )*
        $evis:vis enum $ename:ident {
            $(
                $( #[$vattr:meta] )*
                $vname:ident = $vord:literal,
            )+
        }
        all_variants=$all_variants_vis:vis $all_variants:ident
    ) => {
        $( #[$eattr] )*
        $evis enum $ename {
            $( $( #[$vattr] )* $vname = $vord, )+
        }

        make_trivial_enum!(
            @impl_toname_fromname_display $ename {
                $( $vname ),+
            }
            $all_variants_vis $all_variants);

        impl crate::utils::ToOrdinal for $ename {
            fn to_ordinal(&self) -> u32 {
                match self {
                    $( Self::$vname => $vord ),+
                }
            }
        }

        impl crate::utils::FromOrdinal for $ename {
            const ALL_ORDINALS: &'static [u32] = &[ $( $vord ),+ ];

            fn from_ordinal(ordinal: u32) -> Result<Self, u32> {
                match ordinal {
                    $( $vord => Ok(Self::$vname), )+
                    _ => Err(ordinal),
                }
            }
        }
    };
}

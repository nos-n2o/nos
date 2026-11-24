//! `#[derive(View)]` expansion (`nos_proto::view`): presentation metadata of
//! a reply struct. Kept out of `lib.rs` so `expand` is unit-testable without
//! a proc-macro context.

use proc_macro2::{Span, TokenStream as Tokens};
use quote::quote;
use syn::{Attribute, Data, DeriveInput, Fields, Ident, LitInt, LitStr};

const UNITS: &[(&str, &str)] = &[
    ("secs", "Secs"),
    ("micros", "Micros"),
    ("bytes", "Bytes"),
    ("mbps", "Mbps"),
    ("count", "Count"),
    ("bool", "Bool"),
    ("text", "Text"),
];

#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // one flag per `#[view]` key
struct Attrs {
    seen: bool,
    brief: bool,
    hidden: bool,
    nested: bool,
    text: bool,
    header: Option<LitStr>,
    key: Option<LitStr>,
    unit: Option<Ident>,
    order: Option<LitInt>,
    sort: Option<&'static str>,
}

fn attrs(list: &[Attribute]) -> syn::Result<Attrs> {
    let mut a = Attrs::default();
    for attr in list.iter().filter(|a| a.path().is_ident("view")) {
        a.seen = true;
        attr.parse_nested_meta(|m| {
            let p = &m.path;
            if p.is_ident("brief") {
                a.brief = true;
            } else if p.is_ident("hidden") {
                a.hidden = true;
            } else if p.is_ident("nested") {
                a.nested = true;
            } else if p.is_ident("text") {
                a.text = true;
            } else if p.is_ident("header") {
                a.header = Some(m.value()?.parse()?);
            } else if p.is_ident("key") {
                a.key = Some(m.value()?.parse()?);
            } else if p.is_ident("unit") {
                let u: Ident = m.value()?.parse()?;
                if !UNITS.iter().any(|(n, _)| u == n) {
                    let all: Vec<_> = UNITS.iter().map(|(n, _)| *n).collect();
                    return Err(syn::Error::new_spanned(
                        u,
                        format!("unit must be one of {}", all.join(", ")),
                    ));
                }
                a.unit = Some(u);
            } else if p.is_ident("order") {
                a.order = Some(m.value()?.parse()?);
            } else if p.is_ident("sort") {
                a.sort = Some(if m.input.peek(syn::Token![=]) {
                    let d: Ident = m.value()?.parse()?;
                    if d == "desc" {
                        "Desc"
                    } else {
                        return Err(syn::Error::new_spanned(
                            d,
                            "sort is `sort` or `sort = desc`",
                        ));
                    }
                } else {
                    "Asc"
                });
            } else {
                return Err(m.error("unknown view key"));
            }
            Ok(())
        })?;
    }
    Ok(a)
}

/// `tx_interval_us` -> `Tx-Interval-Us`.
fn default_header(key: &str) -> String {
    key.split('_')
        .map(|w| {
            let mut c = w.chars();
            c.next()
                .map_or_default(|f| f.to_uppercase().chain(c).collect::<String>())
        })
        .collect::<Vec<_>>()
        .join("-")
}

fn bad(ident: &Ident) -> syn::Error {
    syn::Error::new_spanned(ident, "View needs a struct with named fields (no generics)")
}

pub fn expand(input: &DeriveInput) -> syn::Result<Tokens> {
    let ident = &input.ident;
    let Data::Struct(s) = &input.data else {
        return Err(bad(ident));
    };
    let Fields::Named(named) = &s.fields else {
        return Err(bad(ident));
    };
    if !input.generics.params.is_empty() {
        return Err(bad(ident));
    }
    let (mut keys, mut orders, mut sorts) = (Vec::new(), Vec::new(), 0);
    let mut fields = Vec::new();
    let mut asserts = Vec::new();
    for (idx, f) in named.named.iter().enumerate() {
        let id = f.ident.as_ref().expect("named field");
        let a = attrs(&f.attrs)?;
        let err = |m: &str| syn::Error::new_spanned(id, m);
        if !a.seen {
            return Err(err(
                "every field needs #[view(...)] (`#[view()]` = detail only, shown as text)",
            ));
        }
        if a.hidden && (a.brief || a.sort.is_some() || a.nested || a.unit.is_some()) {
            return Err(err("hidden excludes brief, sort, nested and unit"));
        }
        if a.nested && (a.text || a.unit.is_some()) {
            return Err(err("nested excludes text and unit"));
        }
        if a.sort.is_some() {
            if !a.brief {
                return Err(err("sort requires brief"));
            }
            sorts += 1;
            if sorts > 1 {
                return Err(err("only one field may carry sort"));
            }
        }
        let key = a.key.as_ref().map_or_else(
            || id.to_string().trim_start_matches("r#").to_string(),
            LitStr::value,
        );
        if keys.contains(&key) {
            return Err(err("duplicate view key"));
        }
        keys.push(key.clone());
        let order = if let Some(o) = &a.order {
            let n: u32 = o.base10_parse()?;
            if orders.contains(&n) {
                return Err(err("duplicate view order"));
            }
            orders.push(n);
            n
        } else {
            u32::try_from(idx).expect("field count")
        };
        let header = a
            .header
            .as_ref()
            .map_or_else(|| default_header(&key), LitStr::value);
        let unit = a.unit.as_ref().map_or("Text", |u| {
            UNITS.iter().find(|(n, _)| u == n).expect("checked").1
        });
        let unit = Ident::new(unit, Span::call_site());
        let (brief, hidden) = (a.brief, a.hidden);
        let sort = a.sort.map_or_else(
            || quote!(::core::option::Option::None),
            |s| {
                let s = Ident::new(s, Span::call_site());
                quote!(::core::option::Option::Some(::nos_proto::view::Sort::#s))
            },
        );
        let ty = &f.ty;
        let nested = if a.nested {
            asserts.push(quote! {
                const _: () = assert!(
                    !<#ty as ::nos_proto::view::ViewValue>::LEAF,
                    "a `nested` field must be a struct deriving View"
                );
            });
            quote!(::core::option::Option::Some(|| {
                <#ty as ::nos_proto::view::ViewValue>::view().expect("nested View node")
            }))
        } else {
            if !a.text {
                asserts.push(quote! {
                    const _: () = assert!(
                        <#ty as ::nos_proto::view::ViewValue>::LEAF,
                        "mark the field `nested` or `text`"
                    );
                });
            }
            quote!(::core::option::Option::None)
        };
        fields.push(quote!(::nos_proto::view::Field {
            key: #key,
            header: #header,
            unit: ::nos_proto::view::Unit::#unit,
            brief: #brief,
            hidden: #hidden,
            order: #order,
            sort: #sort,
            nested: #nested,
        }));
    }
    Ok(quote! {
        #(#asserts)*
        impl ::nos_proto::view::ViewValue for #ident {
            const LEAF: bool = false;
            fn view() -> ::core::option::Option<&'static ::nos_proto::view::Node> {
                static NODE: ::nos_proto::view::Node = ::nos_proto::view::Node {
                    fields: &[#(#fields),*],
                };
                ::core::option::Option::Some(&NODE)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! fails {
        ($msg:expr, $($t:tt)*) => {
            assert_eq!(
                expand(&syn::parse_quote!($($t)*)).expect_err("must fail").to_string(),
                $msg
            )
        };
    }

    #[test]
    fn rejects_bad_input_with_the_intended_message() {
        fails!(
            "every field needs #[view(...)] (`#[view()]` = detail only, shown as text)",
            struct S {
                a: u32,
            }
        );
        fails!(
            "unknown view key",
            struct S {
                #[view(wat)]
                a: u32,
            }
        );
        fails!(
            "hidden excludes brief, sort, nested and unit",
            struct S {
                #[view(hidden, brief)]
                a: u32,
            }
        );
        fails!(
            "nested excludes text and unit",
            struct S {
                #[view(nested, text)]
                a: u32,
            }
        );
        fails!(
            "unit must be one of secs, micros, bytes, mbps, count, bool, text",
            struct S {
                #[view(unit = fast)]
                a: u32,
            }
        );
        fails!(
            "only one field may carry sort",
            struct S {
                #[view(brief, sort)]
                a: u32,
                #[view(brief, sort = desc)]
                b: u32,
            }
        );
        fails!(
            "sort requires brief",
            struct S {
                #[view(sort)]
                a: u32,
            }
        );
        fails!(
            "duplicate view key",
            struct S {
                #[view(key = "x")]
                a: u32,
                #[view(key = "x")]
                b: u32,
            }
        );
        fails!(
            "duplicate view order",
            struct S {
                #[view(order = 1)]
                a: u32,
                #[view(order = 1)]
                b: u32,
            }
        );
        let want = "View needs a struct with named fields (no generics)";
        fails!(
            want,
            enum E {
                A,
            }
        );
        fails!(want, struct T(u32););
        fails!(
            want,
            struct G<T> {
                #[view()]
                a: T,
            }
        );
    }

    #[test]
    fn default_header_capitalises_each_word() {
        assert_eq!(default_header("tx_interval_us"), "Tx-Interval-Us");
        assert_eq!(default_header("peer"), "Peer");
    }

    #[test]
    fn accepts_the_full_grammar() {
        let t = expand(&syn::parse_quote!(
            struct S {
                #[view(brief, sort = desc, header = "P", unit = secs, order = 3, key = "wire")]
                r#a: u32,
                #[view(nested)]
                n: Other,
                #[view(text, hidden)]
                t: Kind,
                #[view()]
                d: String,
            }
        ))
        .unwrap()
        .to_string();
        assert!(t.contains("\"wire\"") && t.contains("Desc") && t.contains("Secs"));
    }
}

//! `#[derive(Cli)]`: turns a schema struct or enum into its node of the
//! CLI's config tree (`nos_proto::cli`). On a struct, **every** field must
//! carry `#[cli(...)]` naming its help `topic` (or marking it `key` or
//! `hidden`), so a field can't reach the shell — or be added to the schema —
//! without its CLI documentation.
//!
//! ```ignore
//! #[derive(Cli)]
//! pub struct BgpInstance {
//!     #[cli(key)]
//!     pub name: String,
//!     #[cli(topic = BgpInstanceAsn)]
//!     pub asn: u32,
//!     #[cli(topic = BgpPeerGroupAuth, sugar(word = "md5-password", with = sugar::md5, topic = BgpPeerGroupMd5Password))]
//!     pub auth: Option<BgpAuth>,
//!     #[cli(hidden)]
//!     pub routing_table: Option<String>,
//! }
//! ```
//!
//! Field keys: `topic = Ident` (a `nos_proto::Topic` variant), `key`,
//! `hidden`, `secret` (shown as `<hidden>` by `show config`),
//! `render = path` (the field's `show config` lines, for sugar-only
//! syntax the generic renderer can't write), `words = "…"` (today's CLI spelling), `alias = "…"`
//! (repeatable), `sugar(word = "…", with = path, topic = Ident)`
//! (repeatable), `sugar = "{a}.{b} => {a} x {b}"` (a key-token rewrite,
//! repeatable). A struct needs `Default` (a new element's starting point)
//! unless it says `#[cli(no_default)]`. Enum variants take `words`/`alias`,
//! and `#[default]` marks what `delete` resets a non-optional field to.
//!
//! A field without `#[cli]` does not compile:
//!
//! ```compile_fail
//! #[derive(nos_proto_derive::Cli)]
//! struct Missing {
//!     asn: u32,
//! }
//! ```

mod view;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as Tokens;
use quote::quote;
use syn::{parse_macro_input, Attribute, Data, DeriveInput, Fields, Ident, LitStr, Path};

#[proc_macro_derive(Cli, attributes(cli))]
pub fn derive_cli(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// `#[derive(View)]`: presentation metadata of a reply struct
/// (`nos_proto::view`). Every field must carry `#[view(...)]`; `#[view()]` is
/// "detail only, plain text".
///
/// Keys: `brief` (table column), `hidden` (never shown), `header = "…"`,
/// `unit = secs|micros|bytes|mbps|count|bool|text`, `order = N`,
/// `sort` / `sort = desc` (default row order, needs `brief`, one per struct),
/// `key = "…"` (the JSON key when it differs from the Rust name: serde
/// attributes are not parsed), `nested` (a struct deriving `View`, or an
/// `Option`/`Vec` of one), `text` (a struct/enum rendered as one string).
/// A struct or enum field with neither `nested` nor `text` does not compile.
///
/// A field without `#[view]` does not compile:
///
/// ```compile_fail
/// #[derive(nos_proto_derive::View)]
/// struct Missing {
///     asn: u32,
/// }
/// ```
#[proc_macro_derive(View, attributes(view))]
pub fn derive_view(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    view::expand(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // one flag per `#[cli]` key
struct Attrs {
    topic: Option<Ident>,
    key: bool,
    hidden: bool,
    secret: bool,
    render: Option<Path>,
    words: Option<LitStr>,
    aliases: Vec<LitStr>,
    sugar: Vec<(LitStr, Path, Ident)>,
    templates: Vec<LitStr>,
    no_default: bool,
}

fn attrs(list: &[Attribute]) -> syn::Result<Attrs> {
    let mut a = Attrs::default();
    for attr in list.iter().filter(|a| a.path().is_ident("cli")) {
        attr.parse_nested_meta(|m| {
            if m.path.is_ident("topic") {
                a.topic = Some(m.value()?.parse()?);
            } else if m.path.is_ident("key") {
                a.key = true;
            } else if m.path.is_ident("hidden") {
                a.hidden = true;
            } else if m.path.is_ident("secret") {
                a.secret = true;
            } else if m.path.is_ident("render") {
                a.render = Some(m.value()?.parse()?);
            } else if m.path.is_ident("words") {
                a.words = Some(m.value()?.parse()?);
            } else if m.path.is_ident("alias") {
                a.aliases.push(m.value()?.parse()?);
            } else if m.path.is_ident("no_default") {
                a.no_default = true;
            } else if m.path.is_ident("sugar") && m.input.peek(syn::Token![=]) {
                a.templates.push(m.value()?.parse()?);
            } else if m.path.is_ident("sugar") {
                let (mut word, mut with, mut topic) = (None, None, None);
                m.parse_nested_meta(|s| {
                    if s.path.is_ident("word") {
                        word = Some(s.value()?.parse()?);
                    } else if s.path.is_ident("with") {
                        with = Some(s.value()?.parse()?);
                    } else if s.path.is_ident("topic") {
                        topic = Some(s.value()?.parse()?);
                    } else {
                        return Err(s.error("expected word, with or topic"));
                    }
                    Ok(())
                })?;
                match (word, with, topic) {
                    (Some(w), Some(p), Some(t)) => a.sugar.push((w, p, t)),
                    _ => return Err(m.error("sugar needs word, with and topic")),
                }
            } else {
                return Err(m.error("unknown cli key"));
            }
            Ok(())
        })?;
    }
    Ok(a)
}

fn opt_str(s: Option<&LitStr>) -> Tokens {
    s.map_or_else(
        || quote!(::core::option::Option::None),
        |s| quote!(::core::option::Option::Some(#s)),
    )
}

/// One `Field` literal; `required` is true on a struct's own fields.
fn field(f: &syn::Field, required: bool) -> syn::Result<Tokens> {
    let name = f
        .ident
        .as_ref()
        .expect("named field")
        .to_string()
        .trim_start_matches("r#")
        .to_string();
    let a = attrs(&f.attrs)?;
    if required && !(a.topic.is_some() || a.key || a.hidden) {
        return Err(syn::Error::new_spanned(
            f.ident.as_ref(),
            "every schema field needs #[cli(topic = …)] (or `key` / `hidden`): \
             its CLI help lives in nos-config under that Topic",
        ));
    }
    let topic = a.topic.as_ref().map_or_else(
        || quote!(::core::option::Option::None),
        |t| quote!(::core::option::Option::Some(::nos_proto::Topic::#t)),
    );
    let (key, hidden, secret, words) = (a.key, a.hidden, a.secret, opt_str(a.words.as_ref()));
    let render = a.render.as_ref().map_or_else(
        || quote!(::core::option::Option::None),
        |p| quote!(::core::option::Option::Some(#p as ::nos_proto::cli::RenderFn)),
    );
    let (aliases, templates) = (&a.aliases, &a.templates);
    let sugar = a.sugar.iter().map(|(w, p, t)| {
        quote!(::nos_proto::cli::Sugar { word: #w, with: #p, topic: ::nos_proto::Topic::#t })
    });
    let ty = &f.ty;
    Ok(quote!(::nos_proto::cli::Field {
        name: #name,
        topic: #topic,
        hidden: #hidden,
        secret: #secret,
        render: #render,
        key: #key,
        words: #words,
        aliases: &[#(#aliases),*],
        sugar: &[#(#sugar),*],
        templates: &[#(#templates),*],
        kind: <#ty as ::nos_proto::cli::CliValue>::kind,
    }))
}

fn expand(input: &DeriveInput) -> syn::Result<Tokens> {
    let ident = &input.ident;
    let body = match &input.data {
        Data::Struct(s) => {
            let Fields::Named(named) = &s.fields else {
                return Err(syn::Error::new_spanned(ident, "Cli needs named fields"));
            };
            let fields = named
                .named
                .iter()
                .map(|f| field(f, true))
                .collect::<syn::Result<Vec<_>>>()?;
            let default = if attrs(&input.attrs)?.no_default {
                quote!(::core::option::Option::None)
            } else {
                quote!(::core::option::Option::Some(::nos_proto::cli::default_json::<#ident>))
            };
            quote! {
                static NODE: ::nos_proto::cli::Node = ::nos_proto::cli::Node {
                    fields: &[#(#fields),*],
                    default: #default,
                };
                ::nos_proto::cli::Kind::Struct(&NODE)
            }
        }
        Data::Enum(e) => {
            let variants = e
                .variants
                .iter()
                .map(|v| {
                    let name = v.ident.to_string();
                    let a = attrs(&v.attrs)?;
                    let words = opt_str(a.words.as_ref());
                    let aliases = &a.aliases;
                    let default = v.attrs.iter().any(|a| a.path().is_ident("default"));
                    let payload = match &v.fields {
                        Fields::Unit => quote!(::nos_proto::cli::Payload::Unit),
                        Fields::Unnamed(u) if u.unnamed.len() == 1 => {
                            let ty = &u.unnamed[0].ty;
                            quote!(::nos_proto::cli::Payload::Newtype(
                                <#ty as ::nos_proto::cli::CliValue>::kind
                            ))
                        }
                        Fields::Named(n) => {
                            let fields = n
                                .named
                                .iter()
                                .map(|f| field(f, false))
                                .collect::<syn::Result<Vec<_>>>()?;
                            quote!(::nos_proto::cli::Payload::Struct(&[#(#fields),*]))
                        }
                        Fields::Unnamed(_) => {
                            return Err(syn::Error::new_spanned(
                                v,
                                "Cli supports one-field tuple variants only",
                            ))
                        }
                    };
                    Ok(quote!(::nos_proto::cli::Variant {
                        name: #name,
                        words: #words,
                        aliases: &[#(#aliases),*],
                        default: #default,
                        payload: #payload,
                    }))
                })
                .collect::<syn::Result<Vec<_>>>()?;
            quote! {
                static VARIANTS: &[::nos_proto::cli::Variant] = &[#(#variants),*];
                ::nos_proto::cli::Kind::Enum(VARIANTS)
            }
        }
        Data::Union(_) => return Err(syn::Error::new_spanned(ident, "Cli can't derive a union")),
    };
    Ok(quote! {
        impl ::nos_proto::cli::CliValue for #ident {
            fn kind() -> ::nos_proto::cli::Kind {
                #body
            }
        }
    })
}

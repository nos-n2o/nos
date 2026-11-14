use serde::{Deserialize, Serialize};

use crate::schema::{Config, ConversationRange};

use super::OpError;

/// An edit to the explicit LACP conversation map of a named `PortAggregate`
/// (`lacp_conversation_map`, keyed by the range's `first`). Applied without
/// validation, like every `Op`; range/member rules run at commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortAggregateConversationOp {
    /// Adds the range, or replaces the one with the same `first`.
    Add {
        /// Name of the port aggregate this op targets.
        name: String,
        /// First conversation id of the range.
        first: u16,
        /// Last conversation id of the range, inclusive.
        last: u16,
        /// Member interface carrying the range.
        member: String,
    },
    /// Removes the range starting at `first`.
    Remove {
        /// Name of the port aggregate this op targets.
        name: String,
        /// First conversation id of the range to remove.
        first: u16,
    },
    /// Empties the map (back to automatic distribution).
    Clear {
        /// Name of the port aggregate this op targets.
        name: String,
    },
}

impl PortAggregateConversationOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        let name = match self {
            Self::Add { name, .. } | Self::Remove { name, .. } | Self::Clear { name } => name,
        };
        let agg = config
            .port_aggregates
            .iter_mut()
            .find(|a| &a.name == name)
            .ok_or_else(|| OpError::PortAggregateNotFound(name.clone()))?;
        let map = &mut agg.lacp_conversation_map;
        match self {
            Self::Add {
                first,
                last,
                member,
                ..
            } => {
                let range = ConversationRange {
                    first: *first,
                    last: *last,
                    member: member.clone(),
                };
                match map.iter_mut().find(|r| r.first == *first) {
                    Some(existing) => *existing = range,
                    None => map.push(range),
                }
            }
            Self::Remove { first, .. } => {
                let before = map.len();
                map.retain(|r| r.first != *first);
                if map.len() == before {
                    return Err(OpError::LacpConversationNotFound {
                        name: name.clone(),
                        first: *first,
                    });
                }
            }
            Self::Clear { .. } => map.clear(),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::PortAggregate;

    fn cfg() -> Config {
        Config {
            port_aggregates: vec![PortAggregate {
                name: "bond".into(),
                ..PortAggregate::default()
            }],
            ..Config::default()
        }
    }

    fn add(first: u16, last: u16) -> PortAggregateConversationOp {
        PortAggregateConversationOp::Add {
            name: "bond".into(),
            first,
            last,
            member: "eth1".into(),
        }
    }

    #[test]
    fn add_replace_remove_clear() {
        let mut c = cfg();
        add(1, 10).apply(&mut c).unwrap();
        add(20, 30).apply(&mut c).unwrap();
        add(1, 5).apply(&mut c).unwrap();
        let map = &c.port_aggregates[0].lacp_conversation_map;
        assert_eq!(map.len(), 2);
        assert_eq!(map[0].last, 5);
        PortAggregateConversationOp::Remove {
            name: "bond".into(),
            first: 1,
        }
        .apply(&mut c)
        .unwrap();
        assert_eq!(c.port_aggregates[0].lacp_conversation_map.len(), 1);
        PortAggregateConversationOp::Clear {
            name: "bond".into(),
        }
        .apply(&mut c)
        .unwrap();
        assert_eq!(c.port_aggregates[0].lacp_conversation_map, Vec::new());
    }

    #[test]
    fn missing_targets_error() {
        let mut c = cfg();
        assert!(matches!(
            PortAggregateConversationOp::Remove {
                name: "bond".into(),
                first: 9
            }
            .apply(&mut c),
            Err(OpError::LacpConversationNotFound { first: 9, .. })
        ));
        let mut empty = Config::default();
        assert!(matches!(
            add(1, 2).apply(&mut empty),
            Err(OpError::PortAggregateNotFound(_))
        ));
    }
}

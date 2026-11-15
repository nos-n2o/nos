//! The log messages of the core and engine, frozen (#323): the e2e phases
//! (`phases::stp`) and operators grep for these strings, so a log site must
//! use the constant (`info!(port = %p, "{}", events::PORT_ROLE_CHANGED)`) and
//! the table in the tests pins the text. Fields follow the message in the
//! order the site declares them (`docs/protocols/stp.md`, "Log lines").

pub const ROOT_CHANGED: &str = "root bridge changed";
pub const PVST_ROOT_CHANGED: &str = "pvst root bridge changed";
pub const PORT_STATE_CHANGED: &str = "port state changed";
pub const PVST_PORT_STATE_CHANGED: &str = "pvst port state changed";
pub const PORT_ROLE_CHANGED: &str = "port role changed";
pub const PVST_PORT_ROLE_CHANGED: &str = "pvst port role changed";
pub const TOPOLOGY_CHANGE: &str = "topology change";
pub const PORT_MIGRATED_RSTP: &str = "port migrated to RSTP";
pub const PORT_MIGRATED_STP: &str = "port migrated to STP";
pub const PVST_PORT_MIGRATED_RSTP: &str = "pvst port migrated to RSTP";
pub const PVST_PORT_MIGRATED_STP: &str = "pvst port migrated to STP";
pub const PORT_ERR_DISABLED: &str = "port err-disabled";
pub const PORT_ERR_RECOVERED: &str = "port err-disabled recovered";
pub const ERR_DISABLED_READ_FAILED: &str =
    "cannot read the err-disabled ports from nos-interfaced, releasing none";
pub const PORT_ROOT_INCONSISTENT: &str = "port root-inconsistent";
pub const PORT_ROOT_CONSISTENT: &str = "port root-consistent";
pub const PORT_LOOP_INCONSISTENT: &str = "port loop-inconsistent";
pub const PORT_LOOP_CONSISTENT: &str = "port loop-consistent";
pub const NOT_QUIESCENT: &str = "spanning tree state machines did not reach quiescence";
pub const MST_CONFIGURATION: &str = "mst configuration";
pub const MST_BOUNDARY_PORT: &str = "mst boundary port";
pub const MST_REGION_MATCH: &str = "mst region match";
pub const MSTI_PORT_ROLE_CHANGED: &str = "msti port role changed";
pub const MSTI_PORT_STATE_CHANGED: &str = "msti port state changed";
pub const MSTI_ROOT_CHANGED: &str = "msti root bridge changed";
pub const PLAN_UPDATED_IN_PLACE: &str = "spanning tree plan updated in place";
pub const PVID_INCONSISTENT: &str = "pvid inconsistent";
pub const PVID_CONSISTENT: &str = "pvid consistent";

#[cfg(test)]
mod tests {
    use super::*;

    /// Every message, with the text the e2e phases and docs anchor on. Edit a
    /// message only together with `phases::stp` and `docs/protocols/stp.md`.
    #[test]
    fn messages_are_frozen() {
        let table = [
            (ROOT_CHANGED, "root bridge changed"),
            (PVST_ROOT_CHANGED, "pvst root bridge changed"),
            (PORT_STATE_CHANGED, "port state changed"),
            (PVST_PORT_STATE_CHANGED, "pvst port state changed"),
            (PORT_ROLE_CHANGED, "port role changed"),
            (PVST_PORT_ROLE_CHANGED, "pvst port role changed"),
            (TOPOLOGY_CHANGE, "topology change"),
            (PORT_MIGRATED_RSTP, "port migrated to RSTP"),
            (PORT_MIGRATED_STP, "port migrated to STP"),
            (PVST_PORT_MIGRATED_RSTP, "pvst port migrated to RSTP"),
            (PVST_PORT_MIGRATED_STP, "pvst port migrated to STP"),
            (PORT_ERR_DISABLED, "port err-disabled"),
            (PORT_ERR_RECOVERED, "port err-disabled recovered"),
            (
                ERR_DISABLED_READ_FAILED,
                "cannot read the err-disabled ports from nos-interfaced, releasing none",
            ),
            (PORT_ROOT_INCONSISTENT, "port root-inconsistent"),
            (PORT_ROOT_CONSISTENT, "port root-consistent"),
            (PORT_LOOP_INCONSISTENT, "port loop-inconsistent"),
            (PORT_LOOP_CONSISTENT, "port loop-consistent"),
            (
                NOT_QUIESCENT,
                "spanning tree state machines did not reach quiescence",
            ),
            (MST_CONFIGURATION, "mst configuration"),
            (MST_BOUNDARY_PORT, "mst boundary port"),
            (MST_REGION_MATCH, "mst region match"),
            (MSTI_PORT_ROLE_CHANGED, "msti port role changed"),
            (MSTI_PORT_STATE_CHANGED, "msti port state changed"),
            (MSTI_ROOT_CHANGED, "msti root bridge changed"),
            (PLAN_UPDATED_IN_PLACE, "spanning tree plan updated in place"),
            (PVID_INCONSISTENT, "pvid inconsistent"),
            (PVID_CONSISTENT, "pvid consistent"),
        ];
        for (got, want) in table {
            assert_eq!(got, want);
        }
    }
}

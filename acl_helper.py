"""
ACL Builder — a small Streamlit tool that builds Cisco access-lists rule by rule.

What it demonstrates that the subnet calculator did not:
  * st.session_state to hold an ordered, growing list of rules across reruns
  * CIDR -> ACL syntax translation (wildcard masks, host/any shorthand)

Run it:  streamlit run acl_builder.py
"""

import ipaddress
import streamlit as st

# ------------------------------------------------------------------ helpers
def to_acl_target(text):
    """
    Turn user input into Cisco ACL address syntax.
      'any'            -> 'any'
      '10.0.0.5/32'    -> 'host 10.0.0.5'
      '192.168.10.0/24'-> '192.168.10.0 0.0.0.255'
    Raises ValueError on bad input so the caller can show an error.
    """
    text = text.strip()
    if text.lower() == "any":
        return "any"

    # allow a bare host with no prefix, e.g. "10.0.0.5"
    if "/" not in text:
        text = f"{text}/32"

    net = ipaddress.ip_network(text, strict=False)

    if net.prefixlen == 32:
        return f"host {net.network_address}"
    if net.num_addresses == (2 ** 32):          # 0.0.0.0/0
        return "any"
    return f"{net.network_address} {net.hostmask}"


def build_rule_line(rule):
    """Assemble one ACL line from a stored rule dict."""
    parts = [rule["action"], rule["protocol"], rule["source"], rule["destination"]]
    if rule["port"]:
        parts.append(f"eq {rule['port']}")
    return " ".join(parts)


# ------------------------------------------------------------------ state
# This is the new concept: a list that survives reruns and grows on each click.
if "rules" not in st.session_state:
    st.session_state.rules = []

# ------------------------------------------------------------------ header
st.title("ACL Builder")
st.caption("Build Cisco access-lists rule by rule — wildcard masks auto-computed, "
           "config generated ready to paste.")

# ------------------------------------------------------------------ ACL setup
setup1, setup2 = st.columns([1, 2])
with setup1:
    acl_type = st.selectbox("ACL type", ["Extended", "Standard"])
with setup2:
    acl_name = st.text_input("Name / number", value="BLOCK_GUEST")

st.divider()

# ------------------------------------------------------------------ rule builder
st.subheader("Add a rule")

with st.form("rule_form"):
    r1c1, r1c2, r1c3 = st.columns([1, 1, 2])
    with r1c1:
        action = st.selectbox("Action", ["permit", "deny"])
    with r1c2:
        # Standard ACLs are source-only and protocol-less; keep it simple here.
        protocol = st.selectbox("Protocol", ["ip", "tcp", "udp", "icmp"],
                                 disabled=(acl_type == "Standard"))
    with r1c3:
        source = st.text_input("Source", value="192.168.10.0/24",
                               placeholder="192.168.10.0/24 or any")

    r2c1, r2c2, r2c3 = st.columns([2, 1, 1])
    with r2c1:
        destination = st.text_input("Destination", value="any",
                                    placeholder="10.0.0.5/32, any, ...",
                                    disabled=(acl_type == "Standard"))
    with r2c2:
        port = st.text_input("Port (eq)", value="",
                             placeholder="443",
                             disabled=(protocol not in ("tcp", "udp")))
    with r2c3:
        st.write("")  # spacer to line the button up with the inputs
        st.write("")
        added = st.form_submit_button("＋ Add rule", use_container_width=True)

if added:
    try:
        src = to_acl_target(source)
        # Standard ACL lines are source-only; extended needs a destination.
        if acl_type == "Standard":
            rule = {"action": action, "protocol": "", "source": src,
                    "destination": "", "port": ""}
        else:
            dst = to_acl_target(destination)
            rule = {"action": action, "protocol": protocol, "source": src,
                    "destination": dst, "port": port.strip()}
        st.session_state.rules.append(rule)
    except ValueError:
        st.error("Check the source/destination — that isn't a valid IP or subnet.")

st.divider()

# ------------------------------------------------------------------ rules list
head, clear = st.columns([3, 1])
with head:
    st.subheader("Rules")
    st.caption("Order matters — ACLs are processed top-down, first match wins.")
with clear:
    st.write("")
    if st.session_state.rules and st.button("Clear all", use_container_width=True):
        st.session_state.rules = []
        st.rerun()

if not st.session_state.rules:
    st.info("No rules yet — add one above.")
else:
    for i, rule in enumerate(st.session_state.rules):
        line_col, del_col = st.columns([10, 1])
        with line_col:
            st.code(build_rule_line(rule), language="text")
        with del_col:
            if st.button("🗑", key=f"del_{i}", help="Remove this rule"):
                st.session_state.rules.pop(i)
                st.rerun()

# ------------------------------------------------------------------ generated config
st.divider()
st.subheader("Generated configuration")

if not st.session_state.rules:
    st.caption("Add a rule to generate the config block.")
else:
    if acl_type == "Standard":
        header = f"ip access-list standard {acl_name}"
    else:
        header = f"ip access-list extended {acl_name}"

    lines = [header] + [f" {build_rule_line(r)}" for r in st.session_state.rules]
    st.code("\n".join(lines), language="text")

    st.info("Remember the implicit **deny ip any any** at the end of every ACL — "
            "anything not explicitly permitted above is dropped.")

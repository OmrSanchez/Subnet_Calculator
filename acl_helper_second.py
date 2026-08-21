import FreeSimpleGUI as sg
import ipaddress


def to_acl_target(text):
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


def port_segment(operator, port):
    """One '<op> <port>' chunk, or '' if there's no port. Handles multi-port strings."""
    port = (port or "").strip()
    return f"{operator} {port}" if port else ""


def build_rule_line(rule):
    """
    Assemble the IN line and its OUT mirror from a stored rule dict.
    The mirror swaps source<->destination AND carries each port with its address,
    so a port always stays attached to the host it belongs to.
    """
    action, protocol = rule["action"], rule["protocol"]
    source, destination = rule["source"], rule["destination"]
    src_port  = port_segment(rule.get("src_port_operator", ""),  rule.get("src_port", ""))
    dest_port = port_segment(rule.get("dest_port_operator", ""), rule.get("dest_port", ""))

    # Standard ACLs match on source only; there is no directional mirror.
    if protocol == "":
        line = " ".join(p for p in [action, source] if p)
        return line, line

    in_parts  = [action, protocol, source,      src_port,  destination, dest_port]
    out_parts = [action, protocol, destination, dest_port, source,      src_port]
    in_line  = " ".join(p for p in in_parts  if p)   # empty ports drop out here
    out_line = " ".join(p for p in out_parts if p)
    return in_line, out_line


def name_acl(acl_name, acl_type):
    kind = "standard" if acl_type == "Standard" else "extended"
    in_acl_name = f"ip access-list {kind} {acl_name}_IN"
    out_acl_name = f"ip access-list {kind} {acl_name}_OUT"
    return in_acl_name, out_acl_name


def build_remark(src_site, dest_site, service):
    in_remark = f"remark ******* Permit {src_site} to {dest_site} {service.upper()} *********"
    out_remark = f"remark ******* Permit {dest_site} to {src_site} {service.upper()} *********"
    return in_remark, out_remark


def save_to_file(acl_name, rules_for_in, rules_for_out):
    with open(f"{acl_name}.txt", 'w', encoding="utf-8") as file:
        file.writelines(rules_for_in)
        file.write("\n\n")
        file.writelines(rules_for_out)


# ---------------------------------------------------------------- validation
# Two concerns, kept separate:
#   validate_target -> is this a real IP/subnet? (ipaddress is the source of truth)
#   validate_ports  -> does this obey THIS form's port rules? (our own UI contract)
def validate_target(ip_text, cidr_text, field_name):
    """
    Validate one IP + CIDR field pair. Returns (acl_target, None) on success or
    (None, error_message) on failure. One value in, one verdict out.

    ipaddress owns the address grammar (bad octets, /33, etc.). We only add the
    form-convention slash rule and a friendly, field-specific message on top.
    """
    ip_text = ip_text.strip()
    cidr_text = cidr_text.strip()

    if ip_text.lower() == "any":
        return "any", None

    # Form convention: if a prefix is given it must carry a leading slash.
    # Blank prefix is allowed and means a /32 host.
    if cidr_text and not cidr_text.startswith("/"):
        return None, f"{field_name}: prefix must start with '/' (e.g. /24), or leave blank for a host"

    try:
        target = to_acl_target(f"{ip_text}{cidr_text}")   # to_acl_target appends /32 if blank
    except ValueError:
        return None, f"{field_name}: '{ip_text}{cidr_text}' isn't a valid IP or subnet"

    return target, None


def validate_ports(raw, field_name):
    """Form-convention check on one port field. Returns error string or None."""
    raw = raw.strip()
    if not raw:
        return None
    ports = raw.split()
    if len(ports) > 4:
        return f"{field_name}: maximum of 4 ports per line"
    if not all(p.isdigit() for p in ports):
        return f"{field_name}: ports must be numbers separated by spaces"
    return None


# ---------------------------------------------------------------- layout
sg.theme("Gray Gray Gray")

preview = [[sg.Push(),
            sg.Multiline("(IN PREVIEW) Name your ACL and add rules..", size=(80, 15), disabled=True, key="--IN_PREVIEW--"),
            sg.Multiline("(OUT PREVIEW) Name your ACL and add rules..", disabled=True, size=(80, 15), key="--OUT_PREVIEW--"),
            sg.Push()]]
warning = [[sg.Text('', key='--ERROR--', text_color='red', font=('Helvetica', 10, 'bold'))]]

title_layout = [
    [sg.Text("ACL Type    "), sg.Combo(["Standard", "Extended"], default_value='Extended', readonly=True, key="--ACL_TYPE--"),
     sg.Text("ACL Name"), sg.InputText(default_text="NAME_HERE", key="--ACL_NAME--"),
     sg.Button("Export to File", key="--EXPORT--", disabled=True, disabled_button_color="Gray")],
    [sg.HorizontalSeparator()],
    [sg.Text("Remark"), sg.Text("Src LID/FAC"), sg.InputText(default_text='LID/FAC1', size=(12), key="--SRC_REMARK--"),
     sg.Text("Dest LID/FAC"), sg.InputText(default_text='LID/FAC2', size=(12), key="--DEST_REMARK--"),
     sg.Text("Service"), sg.InputText(default_text='Service', size=(12), key="--SVC--"), sg.Button("+ Add", key="--Add_Remark--")],
]

line_layout = [
    [sg.Text('Action       '), sg.Combo(['permit', 'deny'], default_value='permit', readonly=True, key="--ACTION--"),
     sg.Text('         Protocol'), sg.Combo(['ip', 'tcp', 'udp', 'icmp'], default_value='ip', readonly=True, key="--PROTOCOL--")],
    [sg.Text('Source      '), sg.InputText(default_text='192.168.1.1', size=(14), key="--SOURCE_IP--"),
     sg.Text('CIDR'), sg.InputText(default_text='/24', size=(4), key="--SRC_CIDR--"),
     sg.Text('Port'), sg.Combo(['eq', 'neq', 'gt', 'lt', 'range'], default_value='eq', readonly=True, key="--SRC_PO--"),
     sg.InputText(default_text='22', size=(20), key="--SOURCE_PORT--")],
    [sg.Text('Destination'), sg.InputText(default_text="192.168.2.1", size=(14), key="--DESTINATION_IP--"),
     sg.Text('CIDR'), sg.InputText(default_text="/24", size=(4), key="--DEST_CIDR--"),
     sg.Text('Port'), sg.Combo(['eq', 'neq', 'gt', 'lt', 'range'], default_value='eq', readonly=True, key="--DEST_PO--"),
     sg.InputText(default_text='22', size=(20), key="--DEST_PORT--")],
]

editing_layout = [
    [sg.Column(title_layout)],
    [sg.Column(line_layout)],
    [sg.Button(button_text="+ Add rule", key="--Add_Rule--"), sg.Push(),
     sg.Text("", key="--WHERE_OUTPUT--", text_color='green', font=('Helvetica', 10, 'bold'))]
]

layout = [[sg.Push(), sg.Text("ACL HELPER", font="bold 15"), sg.Push()],
          [sg.Push(), sg.Column(editing_layout), sg.Push()],
          [[preview]],
          [[warning]]]

window = sg.Window("ACL Helper", layout, grab_anywhere=True, resizable=True)

in_rule_lines = []
out_rule_lines = []
in_rule_strings = ""
out_rule_strings = ""


def lock_header_controls():
    """Once building has started, freeze the ACL name/type so the filename can't drift."""
    window["--ACL_NAME--"].update(readonly=True, background_color="gray")
    window["--ACL_TYPE--"].update(disabled=True)
    window["--EXPORT--"].update(disabled=False)


def refresh_previews():
    global in_rule_strings, out_rule_strings
    in_rule_strings = "\n".join(in_rule_lines)
    out_rule_strings = "\n".join(out_rule_lines)
    window["--IN_PREVIEW--"].update(in_rule_strings)
    window["--OUT_PREVIEW--"].update(out_rule_strings)


def append_block(in_name, out_name, in_text, out_text):
    """Add the ACL header once, then the new IN/OUT lines."""
    if in_name not in in_rule_lines:
        in_rule_lines.append(in_name)
    in_rule_lines.append(f" {in_text}")
    if out_name not in out_rule_lines:
        out_rule_lines.append(out_name)
    out_rule_lines.append(f" {out_text}")


# ---------------------------------------------------------------- event loop
while True:
    event, values = window.read()

    if event == sg.WIN_CLOSED or event == "Exit":
        break

    if event == "--Add_Rule--":
        is_standard = values["--ACL_TYPE--"] == "Standard"

        # 1) form-convention checks first (ports) — each field, its own message
        error = (validate_ports(values["--SOURCE_PORT--"], "Source port")
                 or validate_ports(values["--DEST_PORT--"], "Destination port"))

        # 2) address validity — ipaddress is the source of truth, per field
        src = dst = None
        if not error:
            src, error = validate_target(values["--SOURCE_IP--"], values["--SRC_CIDR--"], "Source")
        if not error and not is_standard:
            dst, error = validate_target(values["--DESTINATION_IP--"], values["--DEST_CIDR--"], "Destination")

        if error:
            window["--ERROR--"].update(error)
        else:
            window["--ERROR--"].update("")
            lock_header_controls()

            if is_standard:
                rule = {"action": values["--ACTION--"], "protocol": "", "source": src,
                        "destination": "", "src_port_operator": "", "src_port": "",
                        "dest_port_operator": "", "dest_port": ""}
            else:
                rule = {"action": values["--ACTION--"], "protocol": values["--PROTOCOL--"],
                        "source": src, "destination": dst,
                        "src_port_operator": values["--SRC_PO--"], "src_port": values["--SOURCE_PORT--"].strip(),
                        "dest_port_operator": values["--DEST_PO--"], "dest_port": values["--DEST_PORT--"].strip()}

            in_line, out_line = build_rule_line(rule)
            in_name, out_name = name_acl(values["--ACL_NAME--"], values["--ACL_TYPE--"])
            append_block(in_name, out_name, in_line, out_line)
            refresh_previews()

    if event == "--Add_Remark--":
        lock_header_controls()
        in_remark, out_remark = build_remark(values["--SRC_REMARK--"], values["--DEST_REMARK--"], values["--SVC--"])
        in_name, out_name = name_acl(values["--ACL_NAME--"], values["--ACL_TYPE--"])
        append_block(in_name, out_name, in_remark, out_remark)
        refresh_previews()

    if event == "--EXPORT--":
        try:
            save_to_file(values["--ACL_NAME--"], in_rule_strings, out_rule_strings)
            window["--WHERE_OUTPUT--"].update(f"Output file: {values['--ACL_NAME--']}.txt")
        except (OSError, ValueError):
            window["--ERROR--"].update("Something went wrong. Save failed.")

window.close()

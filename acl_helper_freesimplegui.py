import FreeSimpleGUI as sg
import ipaddress
from attr.validators import disabled

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

def build_rule_line(rule):
    """Assemble one ACL line from a stored rule dict."""
    in_parts = [rule["action"], rule["protocol"], rule["source"], rule["destination"]]
    out_parts = [rule["action"], rule["protocol"], rule["destination"], rule["source"]]

    src_port_list = rule["src_port"].split()
    dest_port_list = rule["dest_port"].split()
    # print(type(src_port))

    if rule["dest_port"] == True and rule["src_port"] == True:
        in_parts.insert(3, f"{rule['src_port_operator']} {rule['src_port']}")
        in_parts.append(f"{rule['dest_port_operator']} {rule['dest_port']}")
        out_parts.append(f"{rule['src_port_operator']} {rule['src_port']}")
        out_parts.insert(3, f"{rule['dest_port_operator']} {rule['dest_port']}")

    if rule["dest_port"]:
        in_parts.append(f"{rule['dest_port_operator']} {rule['dest_port']}")
        out_parts.insert(3, f"{rule['dest_port_operator']} {rule['dest_port']}")

    if rule["src_port"]:
        in_parts.insert(3, f"{rule['src_port_operator']} {rule['src_port']}")
        out_parts.append(f"{rule['src_port_operator']} {rule['src_port']}")

    in_line = " ".join(in_parts)
    out_line = " ".join(out_parts)

    return in_line, out_line

def name_acl(acl_name, acl_type):
    if acl_type == "Standard":
        in_acl_name = f"ip access-list standard {acl_name}_IN"
        out_acl_name = f"ip access-list standard {acl_name}_OUT"
    else:
        in_acl_name = f"ip access-list extended {acl_name}_IN"
        out_acl_name = f"ip access-list extended {acl_name}_OUT"
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

sg.theme("Gray Gray Gray")

preview = [[sg.Push(), sg.Multiline("(IN PREVIEW) Name your ACL and add rules..", size=(80,15), disabled=True, key="--IN_PREVIEW--"), sg.Multiline("(OUT PREVIEW) Name your ACL and add rules..", disabled=True, size=(80,15), key="--OUT_PREVIEW--"), sg.Push()]]
warning = [[sg.Text('', key='--ERROR--', text_color='red', font=('Helvetica', 10, 'bold'))]]

title_layout = [
        [sg.Text("ACL Type    "), sg.Combo(["Standard","Extended"], default_value='Extended', readonly=True, key="--ACL_TYPE--"), sg.Text("ACL Name"), sg.InputText(default_text="NAME_HERE", key="--ACL_NAME--"), sg.Button("Export to File", key="--EXPORT--", disabled=True, disabled_button_color="Gray")],
        [sg.HorizontalSeparator()],
        [sg.Text("Remark"), sg.Text("Src LID/FAC"), sg.InputText(default_text='LID/FAC1', size=(12), key="--SRC_REMARK--"), sg.Text("Dest LID/FAC"), sg.InputText(default_text='LID/FAC2', size=(12), key="--DEST_REMARK--"), sg.Text("Service"), sg.InputText(default_text='Service', size=(12), key="--SVC--"), sg.Button("+ Add", key="--Add_Remark--")],
        ]

line_layout = [
        [sg.Text('Action       '), sg.Combo(['permit', 'deny'], default_value='permit', readonly=True, key="--ACTION--"), sg.Text('         Protocol'), sg.Combo(['ip', 'tcp', 'udp', 'icmp'], default_value='ip', readonly=True, key="--PROTOCOL--")],
        [sg.Text('Source      '), sg.InputText(default_text='192.168.1.1', size=(14), key="--SOURCE_IP--"), sg.Text('CIDR'), sg.InputText(default_text='/24', size=(4), key="--SRC_CIDR--"), sg.Text('Port'), sg.Combo(['eq', 'neq', 'gt', 'lt', 'range'], default_value='eq', readonly=True, key="--SRC_PO--"), sg.InputText(default_text='22', size=(20), key="--SOURCE_PORT--")],
        [sg.Text('Destination'), sg.InputText(default_text="192.168.2.1", size=(14) , key="--DESTINATION_IP--"), sg.Text('CIDR'), sg.InputText(default_text="/24", size=(4), key="--DEST_CIDR--"), sg.Text('Port'), sg.Combo(['eq', 'neq', 'gt', 'lt', 'range'], default_value='eq', readonly=True, key="--DEST_PO--"), sg.InputText(default_text='22', size=(20), key="--DEST_PORT--")],
        ]

editing_layout = [
                [sg.Column(title_layout)],
                [sg.Column(line_layout)],
                [sg.Button(button_text="+ Add rule", key="--Add_Rule--"), sg.Push(), sg.Text("", key="--WHERE_OUTPUT--", text_color='green', font=('Helvetica', 10, 'bold'))]
                ]
editing_column = sg.Column(editing_layout)

preview_layout = [[preview]]

warning_layout = [[warning]]

layout = [[sg.Push(), sg.Text("ACL HELPER", font="bold 15"), sg.Push()],
          [sg.Push(), editing_column, sg.Push()],
          [preview_layout],
          [warning_layout]
        ]

window = sg.Window("ACL Helper", layout, grab_anywhere=True, resizable=True)

in_rule_lines = []
out_rule_lines = []
output_file = ""

while True:
    event, values = window.read()

    if event == sg.WIN_CLOSED or event == "Exit":
        break

    if event == "--Add_Rule--":
        window["--ACL_NAME--"].update(readonly=True, background_color="gray")
        window["--ACL_TYPE--"].update(disabled=True)
        window["--EXPORT--"].update(disabled=False)

        src_ports_raw_input = values["--SOURCE_PORT--"].strip()
        src_ports = src_ports_raw_input.split()

        dest_ports_raw_input = values["--DEST_PORT--"].strip()
        dest_ports = dest_ports_raw_input.split()

        src_cidr = values["--SRC_CIDR--"]
        dest_cidr = values["--DEST_CIDR--"]

        try:
            src = to_acl_target(f"{values['--SOURCE_IP--']}{values['--SRC_CIDR--']}")

            if values["--ACL_TYPE--"] == "Standard":
                rule = {"action": values["--ACTION--"], "protocol": "", "source": src,
                        "destination": "", "port": ""}
            else:
                dst = to_acl_target(f"{values['--DESTINATION_IP--']}{values['--DEST_CIDR--']}")
                rule = {"action": values["--ACTION--"], "protocol": values["--PROTOCOL--"], "src_port_operator": values["--SRC_PO--"], "source": src, "src_port": src_ports_raw_input, "destination": dst, "dest_port_operator": values["--DEST_PO--"], "dest_port": dest_ports_raw_input}

            in_acl_name_final, out_acl_name_final = name_acl(values["--ACL_NAME--"], values["--ACL_TYPE--"])

            if f"{in_acl_name_final}" not in in_rule_lines:
                in_rule_lines.append(f"{in_acl_name_final}")
                in_rule_lines.append(f" {build_rule_line(rule)[0]}")
            else:
                in_rule_lines.append(f" {build_rule_line(rule)[0]}")

            if f"{out_acl_name_final}" not in out_rule_lines:
                out_rule_lines.append(f"{out_acl_name_final}")
                out_rule_lines.append(f" {build_rule_line(rule)[1]}")
            else:
                out_rule_lines.append(f" {build_rule_line(rule)[1]}")

            in_rule_strings = '\n'.join(in_rule_lines)
            out_rule_strings = '\n'.join(out_rule_lines)

            window["--IN_PREVIEW--"].update(in_rule_strings)
            window["--OUT_PREVIEW--"].update(out_rule_strings)

        except ValueError:
            window["--ERROR--"].update("Check the source/destination — that isn't a valid IP or subnet.")
        except UnboundLocalError:
            window["--ERROR--"].update("Error. Too many ports used in a single line.")

    if event == "--Add_Remark--":
        window["--ACL_NAME--"].update(readonly=True, background_color="gray")
        window["--ACL_TYPE--"].update(disabled=True)
        window["--EXPORT--"].update(disabled=False)

        in_remark_final, out_remark_final = build_remark(values["--SRC_REMARK--"], values["--DEST_REMARK--"], values["--SVC--"])
        in_acl_name_final, out_acl_name_final = name_acl(values["--ACL_NAME--"], values["--ACL_TYPE--"])

        if f"{in_acl_name_final}" not in in_rule_lines:
            in_rule_lines.append(f"{in_acl_name_final}")
            in_rule_lines.append(f" {in_remark_final}")
        else:
            in_rule_lines.append(f" {in_remark_final}")

        if f"{out_acl_name_final}" not in out_rule_lines:
            out_rule_lines.append(f"{out_acl_name_final}")
            out_rule_lines.append(f" {out_remark_final}")
        else:
            out_rule_lines.append(f" {out_remark_final}")

        in_rule_strings = '\n'.join(in_rule_lines)
        out_rule_strings = '\n'.join(out_rule_lines)

        window["--IN_PREVIEW--"].update(in_rule_strings)
        window["--OUT_PREVIEW--"].update(out_rule_strings)

    if event == "--EXPORT--":
        try:
            save_to_file(values["--ACL_NAME--"], in_rule_strings, out_rule_strings)
            output_file = values['--ACL_NAME--']
            window["--WHERE_OUTPUT--"].update(f"Output file: {output_file}.txt")
        except ValueError:
            window["--ERROR--"].update("Something went wrong. Save Failed.")

window.close()

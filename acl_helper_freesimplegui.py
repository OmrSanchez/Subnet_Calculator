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

def build_rule_line(rule):
    """Assemble one ACL line from a stored rule dict."""
    in_parts = [rule["action"], rule["protocol"], rule["source"], rule["destination"]]
    out_parts = [rule["action"], rule["protocol"], rule["destination"], rule["source"]]

    if rule["port"]:
        in_parts.append(f"eq {rule['port']}")
        out_parts.insert(3,f"eq {rule['port']}")

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

def build_remark(user_text):
    return f"remark *******  {user_text}  *********"

sg.theme("SystemDefault1")

rules = [[sg.Text("Rule Order")]]
preview = [[sg.Multiline("Name your ACL and add rules..", disabled=True, size=(60,20), key="--PREVIEW--")]]

editing_labels = [[sg.Text("ACL Type")],
                  [sg.Text("Name/Number")],
                  [sg.HorizontalSeparator()],
                  [sg.Text("Add Remark")],
                  [sg.HorizontalSeparator()],
                  [sg.Text("Add a Rule")],
                  [sg.Text('Action')],
                  [sg.Text('Protocol')],
                  [sg.Text('Source')],
                  [sg.Text('Source Wildcard')],
                  [sg.Text('Destination')],
                  [sg.Text('Destination Wildcard')],
                  [sg.Text('Port (eq)')],
                  ]

editing_user_input = [[sg.Combo(["Standard","Extended"], default_value='Extended', readonly=True, key="--ACL_TYPE--")],
                      [sg.InputText(default_text="acl name", key="--ACL_NAME--"), sg.Text("", key="--WHERE_OUTPUT--")],
                      [sg.HorizontalSeparator()],
                      [sg.InputText(default_text='Permit A to B', key="--Remark--"), sg.Button("+ Add Remark", key="--Add_Remark--")],
                      [sg.HorizontalSeparator()],
                      [sg.Text("")],
                      [sg.Combo(['permit', 'deny'], default_value='permit', readonly=True, key="--ACTION--")],
                      [sg.Combo(['ip', 'tcp', 'udp', 'icmp'], default_value='ip', readonly=True, key="--PROTOCOL--")],
                      [sg.InputText(default_text='192.168.1.1', key="--SOURCE_IP--")],
                      [sg.InputText(default_text='/24', key="--SOURCE_CIDR--")],
                      [sg.InputText(default_text="192.168.2.1", key="--DESTINATION_IP--")],
                      [sg.InputText(default_text="/24", key="--DESTINATION_CIDR--")],
                      [sg.InputText(default_text='22', key="--PORT--")],
                      ]

editing_layout = [[sg.Column(editing_labels), sg.Column(editing_user_input)], [sg.Button(button_text="+ Add rule", key="--Add_Rule--")]]

display_layout = [[sg.Column(layout=preview)]]

editing_column = sg.Column(editing_layout)
display_column = sg.Column(display_layout)
layout = [[sg.Push(), sg.Text("ACL HELPER", font="bold 25"), sg.Push()],
          [editing_column, display_column]
        ]

window = sg.Window("ACL Helper", layout, grab_anywhere=True)

in_rule_lines = []
out_rule_lines = []
output_file = ""

while True:
    event, values = window.read()

    if event == sg.WIN_CLOSED or event == "Exit":
        break

    if event == "--Add_Rule--":
        window["--ACL_NAME--"].update(readonly=True, background_color="gray")
        output_file = values['--ACL_NAME--']
        window["--WHERE_OUTPUT--"].update(f"Output file: {output_file}.txt")

        try:
            src = to_acl_target(f"{values['--SOURCE_IP--']}{values['--SOURCE_CIDR--']}")
            # Standard ACL lines are source-only; extended needs a destination.
            if values["--ACL_TYPE--"] == "Standard":
                rule = {"action": values["--ACTION--"], "protocol": "", "source": src,
                        "destination": "", "port": ""}
            else:
                dst = to_acl_target(f"{values['--DESTINATION_IP--']}{values['--DESTINATION_CIDR--']}")
                rule = {"action": values["--ACTION--"], "protocol": values["--PROTOCOL--"], "source": src,
                        "destination": dst, "port": values["--PORT--"].strip()}

            in_acl_name_final, out_acl_name_final = name_acl(values["--ACL_NAME--"], values["--ACL_TYPE--"])

            if f"{in_acl_name_final}\n" not in in_rule_lines:
                in_rule_lines.append(f"{in_acl_name_final}\n")
                in_rule_lines.append(f" {build_rule_line(rule)[0]}\n")
            else:
                in_rule_lines.append(f" {build_rule_line(rule)[0]}\n")

            if f"\n{out_acl_name_final}\n" not in out_rule_lines:
                out_rule_lines.append(f"\n{out_acl_name_final}\n")
                out_rule_lines.append(f" {build_rule_line(rule)[1]}\n")
            else:
                out_rule_lines.append(f" {build_rule_line(rule)[1]}\n")

            with open(f"{values["--ACL_NAME--"]}.txt", 'w', encoding="utf-8") as file:
                file.writelines(in_rule_lines)
                file.writelines(out_rule_lines)

            with open(f"{values["--ACL_NAME--"]}.txt", 'r', encoding="utf-8") as file:
                content = file.read()
                print(content)

            window["--PREVIEW--"].update(content)

        except ValueError:
            print("Check the source/destination — that isn't a valid IP or subnet.")

    if event == "--Add_Remark--":
        window["--ACL_NAME--"].update(readonly=True, background_color="gray")
        output_file = values['--ACL_NAME--']
        window["--WHERE_OUTPUT--"].update(f"Output file: {output_file}.txt")

        new_remark = build_remark(values["--Remark--"])
        in_acl_name_final, out_acl_name_final = name_acl(values["--ACL_NAME--"], values["--ACL_TYPE--"])

        if f"{in_acl_name_final}\n" not in in_rule_lines:
            in_rule_lines.append(f"{in_acl_name_final}\n")
            in_rule_lines.append(f" {new_remark}\n")
        else:
            in_rule_lines.append(f" {new_remark}\n")

        if f"\n{out_acl_name_final}\n" not in out_rule_lines:
            out_rule_lines.append(f"\n{out_acl_name_final}\n")
            out_rule_lines.append(f" {new_remark}\n")
        else:
            out_rule_lines.append(f" {new_remark}\n")

        with open(f"{values["--ACL_NAME--"]}.txt", 'w', encoding="utf-8") as file:
            file.writelines(in_rule_lines)
            file.writelines(out_rule_lines)

        with open(f"{values["--ACL_NAME--"]}.txt", 'r', encoding="utf-8") as file:
            content = file.read()
            print(content)

        window["--PREVIEW--"].update(content)

window.close()

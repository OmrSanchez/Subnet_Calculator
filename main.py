from ipaddress import IPv4Interface, AddressValueError
import streamlit as st
import ipaddress

df = {
    "Network Address": "",
    "First Usable": "",
    "Last Usable": "",
    "Broadcast Address": "",
    "Total Usable": "",
    "Subnet Mask": "",
    "CIDR": "",
    "Wildcard": "",
    "Version": ""
}

def get_information(user_ip_addr, mask):
    try:
        ip = ipaddress.IPv4Address(user_ip_addr)
        addr4_init = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        df["Network Address"] = str(addr4_init.network_address)
        df["First Usable"] = str(list(addr4_init.hosts())[0])
        df["Last Usable"] = str(list(addr4_init.hosts())[-1])
        df["Broadcast Address"] = str(addr4_init.broadcast_address)
        df["Subnet Mask"] = str(addr4_init.netmask)
        df["CIDR"] = str(addr4_init.prefixlen)
        df["Wildcard"] = str(addr4_init.hostmask)
        df['Version'] = str(ip.version)
        if str(addr4_init.prefixlen) == "31" or str(addr4_init.prefixlen) == "32":
            df["Total Usable"] = str(int(addr4_init.num_addresses))
        else:
            df["Total Usable"] = str(int(addr4_init.num_addresses) - 2)

    except AddressValueError as e:
        st.error(f"Enter a valid IPv4 address!", icon="🚨")
    except ValueError as e:
        st.error(f"Not a valid address or subnet!", icon="🚨")

st.title("Subnet Calculator")

with st.form(border=True, key="subnet_calculation"):
    st.write("Enter an IP Address either subnet mask or CIDR")
    input_col1, input_col2, input_col3 = st.columns([3, 1, 1], gap="small")
    with input_col1:
        user_ip_address = st.text_input(label="IP Address", label_visibility='collapsed', placeholder="192.168.1.1")
    with input_col2:
        user_given_mask = st.text_input(label="MASK", label_visibility='collapsed', placeholder="24")
    with input_col3:
        submitted = st.form_submit_button(label="Calculate")

if submitted:
    get_information(user_ip_address, user_given_mask)

with st.container():
    st.table(df, width="stretch")



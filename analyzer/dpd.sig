# Signatures for tox.
# https://docs.zeek.org/en/master/frameworks/signatures.html
#
# Potential improvements
#   Match on TCP. Not sure which ports but it might be 443 and then you will need better signatures.
#   Use known packet sizes for control messages
#   Look inside the packets as well

# Match any kind of message on known UDP ports.

signature Tox_UDP_port_match_src {
    ip-proto == udp
    src-port == 33445,33446,33447
    enable "spicy_Tox_udp_message"
}

signature Tox_UDP_port_match_dst {
    ip-proto == udp
    dst-port == 33445,33446,33447
    enable "spicy_Tox_udp_message"
}

# We know some of the system message sizes.
# Match these payload sizes on UDP and TCP on packets #starting with x01.

signature Tox_UDP_33 {
    ip-proto == udp
    payload-size == 33
    enable "spicy_Tox_udp_system_message"
}
signature Tox_UDP_51 {
    ip-proto == udp
    payload-size == 51
    enable "spicy_Tox_udp_system_message"
}
signature Tox_UDP_77 {
    ip-proto == udp
    payload-size == 77
    enable "spicy_Tox_udp_system_message"
}
signature Tox_UDP_78 {
    ip-proto == udp
    payload-size == 78
    enable "spicy_Tox_udp_system_message"
}
signature Tox_UDP_82 {
    ip-proto == udp
    payload-size == 82
    enable "spicy_Tox_udp_system_message"
}
signature Tox_UDP_102 {
    ip-proto == udp
    payload-size == 102
    enable "spicy_Tox_udp_system_message"
}
signature Tox_UDP_113 {
    ip-proto == udp
    payload-size == 113
    enable "spicy_Tox_udp_system_message"
}
signature Tox_UDP_171 {
    ip-proto == udp
    payload-size == 171
    enable "spicy_Tox_udp_system_message"
}
signature Tox_UDP_238 {
    ip-proto == udp
    payload-size == 238
    enable "spicy_Tox_udp_system_message"
}
signature Tox_UDP_250 {
    ip-proto == udp
    payload-size == 250
    enable "spicy_Tox_udp_system_message"
}
signature Tox_UDP_354 {
    ip-proto == udp
    payload-size == 354
    enable "spicy_Tox_udp_system_message"
}
signature Tox_UDP_378 {
    ip-proto == udp
    payload-size == 378
    enable "spicy_Tox_udp_system_message"
}
signature Tox_UDP_403 {
    ip-proto == udp
    payload-size == 403
    enable "spicy_Tox_udp_system_message"
}
signature Tox_UDP_416 {
    ip-proto == udp
    payload-size == 416
    enable "spicy_Tox_udp_system_message"
}


signature Tox_TCP_33 {
    ip-proto == tcp
    payload-size == 33
    enable "spicy_Tox_tcp_system_message"
}
signature Tox_TCP_51 {
    ip-proto == tcp
    payload-size == 51
    enable "spicy_Tox_tcp_system_message"
}
signature Tox_TCP_77 {
    ip-proto == tcp
    payload-size == 77
    enable "spicy_Tox_tcp_system_message"
}
signature Tox_TCP_78 {
    ip-proto == tcp
    payload-size == 78
    enable "spicy_Tox_tcp_system_message"
}
signature Tox_TCP_82 {
    ip-proto == tcp
    payload-size == 82
    enable "spicy_Tox_tcp_system_message"
}
signature Tox_TCP_102 {
    ip-proto == tcp
    payload-size == 102
    enable "spicy_Tox_tcp_system_message"
}
signature Tox_TCP_113 {
    ip-proto == tcp
    payload-size == 113
    enable "spicy_Tox_tcp_system_message"
}
signature Tox_TCP_171 {
    ip-proto == tcp
    payload-size == 171
    enable "spicy_Tox_tcp_system_message"
}
signature Tox_TCP_238 {
    ip-proto == tcp
    payload-size == 238
    enable "spicy_Tox_tcp_system_message"
}
signature Tox_TCP_250 {
    ip-proto == tcp
    payload-size == 250
    enable "spicy_Tox_tcp_system_message"
}
signature Tox_TCP_354 {
    ip-proto == tcp
    payload-size == 354
    enable "spicy_Tox_tcp_system_message"
}
signature Tox_TCP_378 {
    ip-proto == tcp
    payload-size == 378
    enable "spicy_Tox_tcp_system_message"
}
signature Tox_TCP_403 {
    ip-proto == tcp
    payload-size == 403
    enable "spicy_Tox_tcp_system_message"
}
signature Tox_TCP_416 {
    ip-proto == tcp
    payload-size == 416
    enable "spicy_Tox_tcp_system_message"
}

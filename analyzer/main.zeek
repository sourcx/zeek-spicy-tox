module Tox;

export {
    redef enum Log::ID += { TOX_LOG };

    # Use this to determine what kind of packet_kinds we want to log. Useful during development.
	global log_specific_packet_kinds: bool = T;
	global log_specific_system_messages: bool = T;

    type Info: record {
		## Time
		ts: time &log &default=network_time();

		## Unique ID for the connection
		uid: string &log;

		## The connection's 4-tuple of endpoint addresses/ports
		id: conn_id &log;

        ## Transport protocol
        proto: transport_proto &log;

        ## Unique set of Tox packet kinds per session
        packet_kind: set[string] &default=string_set() &log;

        ## Unique set of Tox system message lengths per session
        system_messages: set[count] &default=count_set() &log;
    };

    ### Events ###

    # Any kind of Tox message
    global Tox::message: event(c: connection, is_orig: bool, packet_kind: zeek_spicy_tox::PacketKind, payload: string);

    # Any Tox system message
    global Tox::system_message: event(c: connection, is_orig: bool, payload: string);

    # Log event
    global Tox::log_tox: event(rec: Tox::Info);
}

redef record connection += {
	spicy_tox: Tox::Info &optional;
};

const packet_kind_type = {
    [zeek_spicy_tox::PacketKind_PING_RESPONSE] = "PingResponse",
    [zeek_spicy_tox::PacketKind_NODES_REQUEST] = "NodesRequest",
    [zeek_spicy_tox::PacketKind_NODES_RESPONSE] = "NodesResponse",
    [zeek_spicy_tox::PacketKind_COOKIE_REQUEST] = "CookieRequest",
    [zeek_spicy_tox::PacketKind_COOKIE_RESPONSE] = "CookieResponse",
    [zeek_spicy_tox::PacketKind_CRYPTO_HANDSHAKE] = "CryptoHandshake",
    [zeek_spicy_tox::PacketKind_CRYPTO_DATA] = "CryptoData",
    [zeek_spicy_tox::PacketKind_DHT_REQUEST] = "DHTRequest",
    [zeek_spicy_tox::PacketKind_LAN_DISCOVERY] = "LANDiscovery",
    [zeek_spicy_tox::PacketKind_ONION_REQUEST_0] = "OnionRequest0",
    [zeek_spicy_tox::PacketKind_ONION_REQUEST_1] = "OnionRequest1",
    [zeek_spicy_tox::PacketKind_ONION_REQUEST_2] = "OnionRequest2",
    [zeek_spicy_tox::PacketKind_ANNOUNCE_REQUEST] = "AnnounceRequest",
    [zeek_spicy_tox::PacketKind_ANNOUNCE_RESPONSE] = "AnnounceResponse",
    [zeek_spicy_tox::PacketKind_ONION_DATA_REQUEST] = "OnionDataRequest",
    [zeek_spicy_tox::PacketKind_ONION_DATA_RESPONSE] = "OnionDataResponse",
    [zeek_spicy_tox::PacketKind_ONION_RESPONSE_3] = "OnionResponse3",
    [zeek_spicy_tox::PacketKind_ONION_RESPONSE_2] = "OnionResponse2",
    [zeek_spicy_tox::PacketKind_ONION_RESPONSE_1] = "OnionResponse1",
    [zeek_spicy_tox::PacketKind_BOOTSTRAP_INFO] = "BootstrapInfo"
} &default = function(n: zeek_spicy_tox::PacketKind):
                        string { return fmt("Unknown-%s", n); };

function set_session(c: connection)
    {
    if ( ! c?$spicy_tox )
        {
        c$spicy_tox = [$uid=c$uid, $id=c$id, $proto=get_conn_transport_proto(c$id)];
        }
    }

# Add the packet_kind to the Tox::Info record.
function add_message_to_session(c: connection, packet_kind: string)
    {
    set_session(c);
    add c$spicy_tox$packet_kind[packet_kind];
    }

# Add the payload size of a system message to the Tox::Info record.
function add_system_message_to_session(c: connection, payload_size: count)
    {
    set_session(c);
    add c$spicy_tox$system_messages[payload_size];
    }

event Tox::message(c: connection, is_orig: bool, packet_kind: zeek_spicy_tox::PacketKind, payload: string)
{
    # print("Tox message " + packet_kind_type[packet_kind]);

    if (!log_specific_packet_kinds)
    {
        add_message_to_session(c, packet_kind_type[packet_kind]);
    }
    else if (packet_kind != zeek_spicy_tox::PacketKind_PING_RESPONSE &&
             packet_kind != zeek_spicy_tox::PacketKind_NODES_REQUEST &&
             packet_kind != zeek_spicy_tox::PacketKind_NODES_RESPONSE &&
             packet_kind != zeek_spicy_tox::PacketKind_LAN_DISCOVERY)
    {
        add_message_to_session(c, packet_kind_type[packet_kind]);
    }
}

event Tox::system_message(c: connection, is_orig: bool, payload: string)
{
    # print fmt("Tox system message with length %s", |payload|);
    local payload_size: count = |payload|;

    if (!log_specific_system_messages)
    {
        add_system_message_to_session(c, |payload|);
    }
    ## TODO: Implement filter on payload sizes here. Example here is now not printing 33.
    else if (payload_size != 33)
    {
        add_system_message_to_session(c, |payload|);
    }
}

event connection_state_remove(c: connection)
    {
    if (c?$spicy_tox)
        Log::write(Tox::TOX_LOG, c$spicy_tox);
    }

event zeek_init() &priority=5
    {
    Log::create_stream(Tox::TOX_LOG, [$columns=Info, $ev=log_tox, $path="tox"]);
    }

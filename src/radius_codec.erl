-module(radius_codec).

-export([decode_packet/2, attribute_value/2, identify_packet/1]).
-export([encode_response/3, encode_attributes/1]).
-export([encode_request/2]).

-include("radius.hrl").

%% @doc Encode binary RADIUS request.
encode_request(Req = #radius_packet{}, Secret) ->
    Code = Req#radius_packet.code,
    Ident = Req#radius_packet.ident,
    ReqAuth = Req#radius_packet.auth,
    A = Req#radius_packet.attrs,
    {ok, Attrs} = encode_attributes(A),
    Length = <<(20 + byte_size(Attrs)):16>>,
    Auth = erlang:md5([Code, Ident, Length, ReqAuth, Attrs, Secret]),
    Data = [Code, Ident, Length, Auth, Attrs],
    Data.

%% @doc Decode binary RADIUS packet.
-spec decode_packet(Bin :: binary(), Secret :: string()) ->
    {ok, Packet :: #radius_packet{}} | {error, Reason :: term()}.
decode_packet(Bin, Secret) ->
    try
        <<?RADIUS_PACKET>> = Bin,
        case byte_size(Attrs) >= (Length - 20) of
            true ->
                A = decode_attributes(Attrs, []),
                Packet = #radius_packet{
                    code = Code,
                    ident = Ident,
                    auth = Auth,
                    attrs = A
                },
                case attribute_value("Message-Authenticator", A) of
                    undefined ->
                        {ok, Packet};
                    Value ->
                        A1 = lists:keyreplace("Message-Authenticator", 1, A, {"Message-Authenticator", <<0:128>>}),
                        {ok, A2} = encode_attributes(A1),
                        Packet1 = [Code, Ident, <<Length:16>>, Auth, A2],
                        case crypto:md5_mac(Secret, Packet1) of
                            Value ->
                                {ok, Packet};
                            _ ->
                                lager:warn("Invalid Message-Authenticator attribute value", []),
                                {error, invalid_message_authenticator}
                        end
                end;
            false ->
                lager:error(
                    "Malformed RADIUS packet: "
                    "packet size mismatch: ~p instead of ~p",
                    [Length, byte_size(Attrs) + 20]),
                {error, packet_size_mismatch}
        end
    catch
        _:Reason ->
            lager:error(
                "Unable to decode RADIUS packet for the reason ~p", [Reason]),
            {error, Reason}
    end.

%% @doc Returns the value of specified RADIUS attribute
-spec attribute_value(Code :: non_neg_integer() | tuple(), Packet :: #radius_packet{}) ->
    undefined | proplists:property().
attribute_value(Code, Packet) when is_record(Packet, radius_packet) ->
    attribute_value(Code, Packet#radius_packet.attrs);
attribute_value(Code, Attrs) when is_list(Attrs) ->
    case radius_dict:lookup_attribute(Code) of
        not_found ->
            undefined;
        #attribute{code = Code1, name = Name} ->
            lookup_value(Code1, Name, Attrs)
    end.

%% @doc Returns type of the request
-spec identify_packet(Type :: non_neg_integer()) ->
    {ok, atom()} | {unknown, non_neg_integer()}.
identify_packet(?ACCESS_REQUEST) ->
    {ok, 'Access-Request'};
identify_packet(?ACCOUNTING_REQUEST) ->
    {ok, 'Accounting-Request'};
identify_packet(?ACCESS_CHALLENGE) ->
    {ok, 'Access-Challenge'};
identify_packet(?DISCONNECT_REQUEST) ->
    {ok, 'Disconnect-Request'};
identify_packet(?DISCONNECT_ACK) ->
    {ok, 'Disconnect-ACK'};
identify_packet(?DISCONNECT_NAK) ->
    {ok, 'Disconnect-NAK'};
identify_packet(?COA_REQUEST) ->
    {ok, 'CoA-Request'};
identify_packet(?COA_ACK) ->
    {ok, 'CoA-ACK'};
identify_packet(?COA_NAK) ->
    {ok, 'CoA-NAK'};
identify_packet(Type) ->
    {unknown, Type}.


%% @doc Encode RADIUS packet to binary
-spec encode_response(Request :: #radius_packet{},
                      Response :: #radius_packet{},
                      Secret :: string()) ->
    {ok, binary()} | {error, Reason :: term()}.
encode_response(Request, Response, Secret) ->
    #radius_packet{code = C, attrs = A} = Response,
    Code = <<C:8>>,
    Ident = Request#radius_packet.ident,
    ReqAuth = Request#radius_packet.auth,
    case attribute_value("EAP-Message", A) of
        undefined ->
            case encode_attributes(A) of
                {ok, Attrs} ->
                    Length = <<(20 + byte_size(Attrs)):16>>,
                    Auth = erlang:md5([Code, Ident, Length, ReqAuth, Attrs, Secret]),
                    Data = [Code, Ident, Length, Auth, Attrs],
                    {ok, Data};
                 {error, Reason} ->
                     lager:criticial(
                         "Unable to encode RADIUS attributes: ~p "
                         "for the reason: ~p", [A, Reason]),
                    {error, Reason}
            end;
        _Value ->
            try
                A1 = [{"Message-Authenticator", <<0:128>>} | A],
                {ok, A2} = encode_attributes(A1),

                Length = <<(20 + byte_size(A2)):16>>,
                Packet = list_to_binary([Code, Ident, Length, ReqAuth, A2]),
                MA = crypto:md5_mac(Secret, Packet),

                A3 = [{"Message-Authenticator", MA} | A],
                {ok, A4} = encode_attributes(A3),

                Auth = erlang:md5([Code, Ident, Length, ReqAuth, A4, Secret]),
                Data = [Code, Ident, Length, Auth, A4],
                {ok, Data}
            catch
                _:Reason ->
                    lager:error(
                        "Unable to compute Message-Authenticator "
                        "for the reason: ~p "
                        "Attributes were: ~p", [Reason, A]),
                    {error, Reason}
            end
    end.

%% @doc Encode list of RADIUS attributes to binary
-spec encode_attributes(Attrs :: [proplists:property()]) ->
    {ok, binary()} | {error, Reason :: term()}.
encode_attributes(Attrs) ->
    try
        Bin = encode_attributes(Attrs, []),
        {ok, Bin}
    catch
        _:Reason ->
            {error, Reason}
    end.

%%
%% Internal functions
%%
decode_attributes(<<>>, Attrs) ->
    lists:reverse(lists:flatten(Attrs));
decode_attributes(Bin, Attrs) ->
    {Attr, Rest} = decode_attribute(Bin),
    decode_attributes(Rest, [Attr | Attrs]).

decode_attribute(<<Type:8, Length:8, Rest/binary>>) ->
    case Type of
        ?VENDOR_SPECIFIC ->
            L = Length - 2,
            <<Attr:L/binary-unit:8, Rest1/binary>> = Rest,
            {decode_vendor_attributes(Attr), Rest1};
        _ ->
            case radius_dict:lookup_attribute(Type) of
                not_found ->
                    {Value, Rest1} = decode_value(Rest, Length - 2),
                    {{Type, Value}, Rest1};
                A ->
                    {Value, Rest1} = decode_value(Rest, Length - 2, A#attribute.type),
                    {{A#attribute.name, Value}, Rest1}
            end
    end.

decode_vendor_attributes(<<VendorId:4/integer-unit:8, Rest/binary>>) ->
    decode_vendor_attribute(VendorId, Rest, []).

decode_vendor_attribute(_, <<>>, Acc) -> Acc;
decode_vendor_attribute(VendorId, <<Id, Length:8, Value/binary>>, Acc) ->
    case radius_dict:lookup_attribute({VendorId, Id}) of
        not_found ->
            lager:warning("No vendor specific attribute ~p found in dictionary",
                [{VendorId, Id}]),
            {V, Rest1} = decode_value(Value, Length - 2),
            decode_vendor_attribute(VendorId, Rest1, [{{VendorId, Id}, V} | Acc]);
        A ->
            {V, Rest1} = decode_value(Value, Length - 2, A#attribute.type),
            decode_vendor_attribute(VendorId, Rest1, [{A#attribute.name, V} | Acc])
    end.

%% 0-253 octets
decode_value(Bin, Length, string) ->
    <<Value:Length/binary, Rest/binary>> = Bin,
    {binary_to_list(Value), Rest};
%% 32 bit value in big endian order (high byte first)
decode_value(Bin, Length, integer) ->
    <<Value:Length/integer-unit:8, Rest/binary>> = Bin,
    {Value, Rest};
%% 32 bit value in big endian order - seconds since 00:00:00 GMT, Jan. 1, 1970
decode_value(Bin, Length, date) ->
    decode_value(Bin, Length, integer);
%% 4 octets in network byte order
decode_value(Bin, Length, ipaddr) ->
    <<Value:Length/binary, Rest/binary>> = Bin,
    <<A:8, B:8, C:8, D:8>> = Value,
    {{A, B, C, D}, Rest};
decode_value(Bin, Length, ipv6addr) ->
    <<Value:Length/binary, Rest/binary>> = Bin,
    {list_to_tuple([I || <<I:16>> <= Value]), Rest};
decode_value(Bin, Length, ipv6prefix) ->
    IPLength = Length - 2,
    <<0:8, Prefix:8, IP:IPLength/binary, Rest/binary>> = Bin,
    {{Prefix, list_to_tuple([I || <<I:16>> <= IP])}, Rest};
decode_value(Bin, Length, byte) ->
    <<Value:Length/unsigned-integer-unit:8, Rest/binary>> = Bin,
    {Value, Rest};
decode_value(Bin, Length, _Type) ->
    decode_value(Bin, Length).

decode_value(Bin, Length) ->
    <<Value:Length/binary, Rest/binary>> = Bin,
    {Value, Rest}.

encode_attributes(undefined, []) ->
    <<>>;
encode_attributes([], Bin) ->
    list_to_binary(lists:reverse(Bin));
encode_attributes([A | Attrs], Bin) ->
    encode_attributes(Attrs, [encode_attribute(A) | Bin]).

encode_attribute({Code, Value}) ->
    case radius_dict:lookup_attribute(Code) of
        not_found ->
            lager:notice("Unable to lookup attribute ~p in dictionary", [Code]),
            throw({error, not_found});
        #attribute{code = Code1, type = Type} ->
            encode_attribute(Code1, Type, Value)
    end.

encode_attribute({Id, Code}, Type, Value) ->
    Bin = encode_value(Value, Type),
    Size = byte_size(Bin),
    VLength = 8 + Size,
    ALength = 2 + Size,
    <<?VENDOR_SPECIFIC:8, VLength:8, Id:32, Code:8, ALength:8, Bin/binary>>;
encode_attribute(Code, Type, Value) ->
    Bin = encode_value(Value, Type),
    Length = 2 + byte_size(Bin),
    <<Code:8, Length:8, Bin/binary>>.

encode_value(Value, _Type) when is_binary(Value) ->
    Value;
encode_value(Value, octets) when is_list(Value) ->
    list_to_binary(Value);
encode_value(Value, string) when is_list(Value) ->
    list_to_binary(Value);
encode_value(Value, integer) when is_list(Value) ->
    try
        IntValue = list_to_integer(Value),
        <<IntValue:32>>
    catch
        _:Reason ->
            lager:error(
                "Unable to encode attribute value ~p as integer "
                "for the reason: ~p", [Value, Reason]),
            throw({error, Reason})
    end;
encode_value(Value, integer) when is_integer(Value) ->
    <<Value:32>>;
encode_value(Value, date) ->
    encode_value(Value, integer);
encode_value(Value, ipaddr) when is_list(Value) ->
    case inet_parse:address(Value) of
        {ok, {A, B, C, D}} ->
            <<A:8, B:8, C:8, D:8>>;
        {error, Reason} ->
            lager:error(
                "Unable to encode attribute value ~p as ipaddr "
                "for the reason: ~s", [Value, inet:format_error(Reason)]),
            throw({error, Reason})
    end;
encode_value({A, B, C, D}, ipaddr) ->
    <<A:8, B:8, C:8, D:8>>;
encode_value(Value, ipv6addr) when is_list(Value) ->
    case inet_parse:address(Value) of
        {ok, IP} when tuple_size(IP) == 8 ->
            encode_value(IP, ipv6addr);
        {error, Reason} ->
            lager:critical(
                "Unable to encode attribute value ~p as ipv6addr "
                "for the reason: ~s", [Value, inet:format_error(Reason)]),
            throw({error, Reason})
    end;
encode_value(Value, ipv6addr) when tuple_size(Value) == 8 ->
    binary:list_to_bin([<<I:16>> || I <- tuple_to_list(Value)]);
encode_value({Prefix, IP}, ipv6prefix) ->
    list_to_binary([<<0:8, Prefix:8>>, encode_value(IP, ipv6addr)]);
encode_value(Value, byte) ->
    <<Value:8/unsigned-integer>>;
encode_value(Value, Type) ->
    lager:warning(
        "Unable to encode attribute value ~p as ~p", [Value, Type]),
    throw({error, encode_value}).

lookup_value(Code, Name, Attrs) ->
    case lists:keysearch(Code, 1, Attrs) of
        {value, {_, Value}} ->
            Value;
        false ->
            case lists:keysearch(Name, 1, Attrs) of
                {value, {_, Value}} ->
                    Value;
                false ->
                    undefined
            end
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

setup_app() ->
    ok = radius:start(),
    lists:foreach(fun radius_dict:add/1, radius_dict_file:load("dictionary")),
    lists:foreach(fun radius_dict:add/1, radius_dict_file:load("dictionary.nokia")),
    ok.

radius_codec_test_() ->
    {setup, fun setup_app/0, [
                              {generator, fun accounting_request/0},
                              {generator, fun access_request/0}
                             ]}.

make_label(L) when is_binary(L) ->
    L;
make_label(L) when is_list(L) ->
    list_to_binary(L);
make_label(_) ->
    <<"unknown">>.

accounting_request() ->
    Pattern = [{"User-Name","48691003145"},
               {"NAS-IP-Address",{10,1,6,10}},
               {"NAS-Identifier","FI9100XX"},
               {"NAS-Port-Type",5},
               {"Acct-Status-Type",1},
               {"Called-Station-Id","flexi.internet"},
               {"Calling-Station-Id","48691003145"},
               {"Acct-Session-Id","5c3c804d7500f10d"},
               {"Acct-Multi-Session-Id","5c3c804d3a80001b"},
               {"Acct-Link-Count",1},
               {"Class",<<"000000000000000008">>},
               {"Framed-IP-Address",{30,15,4,161}},
               {"Service-Type",2},
               {"Framed-Protocol",7},
               {"Acct-Authentic",1},
               {226,<<0,0,0,8>>},
               {"3GPP-IMSI","260019900003145"},
               {"3GPP-GGSN-Address",{92,60,128,77}},
               {"3GPP-SGSN-Address",{212,2,113,34}},
               {"3GPP-PDP-Type",0},
               {"3GPP-Charging-Gateway-Address",{10,1,4,206}},
               {"3GPP-IMSI-MCC-MNC","26001"},
               {"3GPP-Charging-ID",1962995981},
               {"3GPP-GPRS-Negotiated-QoS-profile",
                "05-13921F739697FE74821040000000"},
               {"3GPP-SGSN-MCC-MNC","26001"},
               {"3GPP-Selection-Mode","1"},
               {"3GPP-Charging-Characteristics","0800"},
               {"3GPP-RAT-Type",1},
               {"3GPP-IMEISV","3560590343456622"},
               {"3GPP-Location-Info",<<1,98,240,16,1,144,255,31>>},
               {"3GPP-MS-Time-Zone",32801},
               {"3GPP-NSAPI","5"},
               {"Nokia-Requested-APN","flexi.internet"},
               {"Nokia-Session-Access-Method",<<1>>},
               {"Nokia-Session-Charging-Type",<<4>>}],
    Packet = <<4,29,1,101,185,58,167,59,234,55,5,176,245,153,78,209,68,36,107,146,1,13,52,
               56,54,57,49,48,48,51,49,52,53,4,6,10,1,6,10,32,10,70,73,57,49,48,48,88,88,61,
               6,0,0,0,5,40,6,0,0,0,1,30,16,102,108,101,120,105,46,105,110,116,101,114,110,
               101,116,31,13,52,56,54,57,49,48,48,51,49,52,53,44,18,53,99,51,99,56,48,52,
               100,55,53,48,48,102,49,48,100,50,18,53,99,51,99,56,48,52,100,51,97,56,48,48,
               48,49,98,51,6,0,0,0,1,25,20,48,48,48,48,48,48,48,48,48,48,48,48,48,48,48,48,
               48,56,8,6,30,15,4,161,6,6,0,0,0,2,7,6,0,0,0,7,45,6,0,0,0,1,226,6,0,0,0,8,26,
               147,0,0,40,175,1,17,50,54,48,48,49,57,57,48,48,48,48,51,49,52,53,7,6,92,60,
               128,77,6,6,212,2,113,34,3,6,0,0,0,0,4,6,10,1,4,206,8,7,50,54,48,48,49,2,6,
               117,0,241,13,5,33,48,53,45,49,51,57,50,49,70,55,51,57,54,57,55,70,69,55,52,
               56,50,49,48,52,48,48,48,48,48,48,48,18,7,50,54,48,48,49,12,3,49,13,6,48,56,
               48,48,21,3,1,20,18,51,53,54,48,53,57,48,51,52,51,52,53,54,54,50,50,22,10,1,
               98,240,16,1,144,255,31,23,4,128,33,10,3,53,26,28,0,0,0,94,15,16,102,108,101,
               120,105,46,105,110,116,101,114,110,101,116,10,3,1,11,3,4>>,
    {ok, #radius_packet{ ident = <<29>>, attrs = Attrs}} = decode_packet(Packet, "foo"),
    [ { make_label(K),
        fun() ->
                ?assertEqual(V, proplists:get_value(K, Attrs))
        end } || {K, V} <- Pattern ].

access_request() ->
    Pattern = [{"NAS-Identifier","FI9100XX"},
               {"User-Name","48691003145"},
               {"NAS-IP-Address",{10,1,6,10}},
               {"NAS-Port-Type",5},
               {"Called-Station-Id","flexi.internet"},
               {"Calling-Station-Id","48691003145"},
               {"Service-Type",2},
               {"Framed-Protocol",7},
               {"3GPP-SGSN-Address",{212,2,113,34}},
               {"3GPP-IMSI","260019900003145"},
               {"3GPP-PDP-Type",0},
               {"3GPP-Charging-Gateway-Address",{10,1,4,206}},
               {"3GPP-GGSN-Address",{92,60,128,77}},
               {"3GPP-IMSI-MCC-MNC","26001"},
               {"3GPP-Charging-ID",1962995981},
               {"3GPP-Selection-Mode","1"},
               {"3GPP-Charging-Characteristics","0800"},
               {"3GPP-GPRS-Negotiated-QoS-profile",
                "05-13921F739697FE74821040000000"},
               {"3GPP-SGSN-MCC-MNC","26001"},
               {"3GPP-IMEISV","3560590343456622"},
               {"3GPP-RAT-Type",1},
               {"3GPP-Location-Info",<<16#01, 16#62, 16#F0, 16#10, 16#01, 16#90, 16#FF, 16#1F>>},
               {"3GPP-MS-Time-Zone",32801},
               {"3GPP-NSAPI","5"},
               {"Nokia-Requested-APN","flexi.internet"},
               {"Acct-Session-Id","5c3c804d7500f10d"},
               {"Acct-Multi-Session-Id","5c3c804d3a80001b"}],
    Packet = <<1,8,1,63,157,72,191,249,0,56,34,174,49,7,66,196,129,253,85,158,32,10,70,73,
               57,49,48,48,88,88,1,13,52,56,54,57,49,48,48,51,49,52,53,2,18,77,215,103,15,
               206,63,153,51,119,222,188,181,76,9,3,93,4,6,10,1,6,10,61,6,0,0,0,5,30,16,102,
               108,101,120,105,46,105,110,116,101,114,110,101,116,31,13,52,56,54,57,49,48,
               48,51,49,52,53,6,6,0,0,0,2,7,6,0,0,0,7,26,147,0,0,40,175,6,6,212,2,113,34,1,
               17,50,54,48,48,49,57,57,48,48,48,48,51,49,52,53,3,6,0,0,0,0,4,6,10,1,4,206,7,
               6,92,60,128,77,8,7,50,54,48,48,49,2,6,117,0,241,13,12,3,49,13,6,48,56,48,48,
               5,33,48,53,45,49,51,57,50,49,70,55,51,57,54,57,55,70,69,55,52,56,50,49,48,52,
               48,48,48,48,48,48,48,18,7,50,54,48,48,49,20,18,51,53,54,48,53,57,48,51,52,51,
               52,53,54,54,50,50,21,3,1,22,10,1,98,240,16,1,144,255,31,23,4,128,33,10,3,53,
               26,22,0,0,0,94,15,16,102,108,101,120,105,46,105,110,116,101,114,110,101,116,
               44,18,53,99,51,99,56,48,52,100,55,53,48,48,102,49,48,100,50,18,53,99,51,99,
               56,48,52,100,51,97,56,48,48,48,49,98>>,
    {ok, #radius_packet{ ident = <<8>>, attrs = Attrs}} = decode_packet(Packet, "foo"),
    [ { make_label(K), fun() ->
                               ?assertEqual(V, proplists:get_value(K, Attrs))
                       end } || {K, V} <- Pattern ].


-endif.

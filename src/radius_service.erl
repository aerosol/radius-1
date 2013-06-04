-module(radius_service).

-behaviour(gen_server).

%% API
-export([start_link/4]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2,
         handle_info/2, code_change/3, terminate/2]).

-include("radius.hrl").

-callback handle_request(Type :: non_neg_integer(),
                         Request :: #radius_packet{},
                         Client :: #nas_spec{}) ->
    {ok, Response :: #radius_packet{}} | noreply.

-record(state, {
    socket :: inet:socket(),
    clients :: [#nas_spec{}],
    callback :: module()
}).

start_link(Name, IP, Port, Callback) ->
    gen_server:start_link({local, Name}, ?MODULE, [IP, Port, Callback], []).

init([IP, Port, Callback] = Options) ->
    process_flag(trap_exit, true),
    case gen_udp:open(Port, [binary, {ip, IP}]) of
        {ok, Socket} ->
            Clients = ets:new(clients, [{keypos, 3}]),
            {ok, #state{socket = Socket, clients = Clients, callback = Callback}};
        {error, Reason} ->
            lager:error(
                "RADIUS service can't start "
                "for the reason ~p: ~s "
                "Options were ~p",
                [Reason, inet:format_error(Reason), Options]),
            {error, Reason}
    end.

handle_call({add_client, NasSpec}, _From, State) ->
    ets:insert(State#state.clients, NasSpec),
    {reply, ok, State};

handle_call({del_client, NasName}, _From, State) ->
    Pattern = {nas_spec, NasName, '_', '_'},
    case ets:match_object(State#state.clients, Pattern) of
        [NasSpec] ->
            ets:delete_object(State#state.clients, NasSpec);
        _ -> ok
    end,
    {reply, ok, State};

handle_call(_, _, State) ->
    {reply, unknown_call, State}.

handle_cast(_Msg, State) -> {noreply, State}.

handle_info({udp, Socket, SrcIP, SrcPort, Bin}, State) ->
    Opts = [SrcIP, SrcPort, Socket, Bin, State],
    proc_lib:spawn_link(fun() -> do_callback(Opts) end),
    {noreply, State};

handle_info({'EXIT', _Pid, normal}, State) -> {noreply, State};
handle_info({'EXIT', _Pid, _Reason}, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

terminate(_Reason, State) ->
    gen_udp:close(State#state.socket).

%%
%% Internal functions
%%
do_callback(Args = [SrcIP, SrcPort, Socket, Bin, State]) ->
    case lookup_client(SrcIP, State#state.clients) of
        {ok, #nas_spec{secret = Secret} = Client} ->
            case radius_codec:decode_packet(Bin, Secret) of
                {ok, Packet} ->
                    case radius_codec:identify_packet(Packet#radius_packet.code) of
                        {ok, Type} ->
                            Callback = State#state.callback,
                            case Callback:handle_request(Type, Packet, Client) of
                                {ok, Response} ->
                                    do_reply(Socket, SrcIP, SrcPort, Response, Packet, Client);
                                noreply ->
                                    nop;
                                Unknown ->
                                    lager:critical("Bad return from handler: ~p", [Unknown])
                            end;
                        {unknown, Unknown} ->
                            lager:notice("Unknown request type: ~p", [Unknown])
                    end;
                _ ->
                    lager:error(
                      "Received invalid packet from NAS: ~s", [inet_parse:ntoa(SrcIP)])
            end;
        undefined ->
            lager:warning(
              "Request from unknown client: ~s", [inet_parse:ntoa(SrcIP)])
    end.

do_reply(Socket, IP, Port, Response, Request, Client) ->
    Secret = Client#nas_spec.secret,
    case radius_codec:encode_response(Request, Response, Secret) of
        {ok, Data} ->
            gen_udp:send(Socket, IP, Port, Data);
        {error, Reason} ->
            lager:critical("Unable to respond to client due to ~p", [Reason])
    end.

lookup_client(IP, Table) ->
    case ets:lookup(Table, IP) of
        [] ->
            undefined;
        [Client] ->
            {ok, Client}
    end.


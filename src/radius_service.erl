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
            error_logger:error_msg(
                "** RADIUS service can't start~n"
                "   for the reason ~p: ~s~n"
                "** Options were ~p~n",
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

handle_call(_Request, _From, State) -> {reply, ok, State}.

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
do_callback([SrcIP, SrcPort, Socket, Bin, State]) ->
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
                                    error_logger:error_msg("Bad return from handler: ~p~n", [Unknown])
                            end;
                        {unknown, Unknown} ->
                            error_logger:warning_msg("Unknown request type: ~p~n", [Unknown])
                    end;
                _ ->
                    error_logger:error_msg(
                      "Received invalid packet from NAS: ~s~n", [inet_parse:ntoa(SrcIP)])
            end;
        undefined ->
            error_logger:warning_msg(
              "Request from unknown client: ~s~n", [inet_parse:ntoa(SrcIP)])
    end.

do_reply(Socket, IP, Port, Response, Request, Client) ->
    Secret = Client#nas_spec.secret,
    case radius_codec:encode_response(Request, Response, Secret) of
        {ok, Data} ->
            gen_udp:send(Socket, IP, Port, Data);
        {error, Reason} ->
            error_logger:error_msg("Unable to respond to client due to ~p~n", [Reason])
    end.

lookup_client(IP, Table) ->
    case ets:lookup(Table, IP) of
        [] ->
            undefined;
        [Client] ->
            {ok, Client}
    end.


-module(radius_server_SUITE).

%% common_test required callbacks
-export([suite/0, sequences/0, all/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).

%% cases
-export([access_request/0, access_request/1]).

%% helpers
-export([handle_request/3]).

-include_lib("common_test/include/ct.hrl").
-include_lib("radius/include/radius.hrl").

-define(SHARED_SECRET, "testing123").
-define(SERVICE_NAME, test_radius_server).

%%---------------------------------------------------------------------
%%  Test server callback functions
%%---------------------------------------------------------------------

%% @spec () -> DefaultData
%%      DefaultData = [tuple()]
%% @doc Require variables and set default values for the suite.
%%
suite() ->
    [{timetrap, {minutes, 1}}].

%% @spec (Config) -> Config
%%      Config = [tuple()]
%% @doc Initiation before the whole suite.
%%
init_per_suite(Config) ->
    SharedSecret = ?SHARED_SECRET,
    NewConfig = [{secret, SharedSecret} | Config],
    ok = radius:start(),
    ok = start_server(),
    NewConfig.

%% @spec (Config) -> any()
%%      Config = [tuple()]
%% @doc Cleanup after the whole suite.
%%
end_per_suite(_Config) ->
    ok = stop_server(),
    ok = application:stop(radius),
    ok = application:stop(lager),
    ok.

%% @spec (TestCase, Config) -> Config
%%      Config = [tuple()]
%% @doc Initiation before each test case.
%%
init_per_testcase(_TestCase, Config) ->
    {ok, Socket} = gen_udp:open(0, [{active, false}, inet,
                                    {ip, {127, 0, 0, 1}}, binary]),
    [{socket, Socket} | Config].

%% @spec (TestCase, Config) -> any()
%%      Config = [tuple()]
%% @doc Cleanup after each test case.
%%
end_per_testcase(start_and_stop, _Config) ->
    ok;
end_per_testcase(_TestCase, Config) ->
    Socket = ?config(socket, Config),
    gen_udp:close(Socket),
    ok.

%% @spec () -> Sequences
%%      Sequences = [{SeqName, Testcases}]
%%      SeqName = atom()
%%      Testcases = [atom()]
%% @doc Group test cases into a test sequence.
%%
sequences() ->
    [].

%% @spec () -> TestCases
%%      TestCases = [Case]
%%      Case = atom()
%% @doc Returns a list of all test cases in this test suite.
%%
all() ->
    [access_request].

%%---------------------------------------------------------------------
%%  Test cases
%%---------------------------------------------------------------------

access_request() ->
    [{userdata, [{doc, "Send a RADIUS access request"}]}].

access_request(Config) ->
    Secret = ?config(secret, Config),
    User = nas1,
    Password = "passWORD!",
    Request = #radius_packet{
                 code = ?ACCESS_REQUEST,
                 ident = <<1>>,
                 auth = <<>>,
                 attrs = []
                },
    Encoded = radius_codec:encode_request(Request, ?SHARED_SECRET),
    Port = 1812,
    Socket = ?config(socket, Config),
    Address = {127,0,0,1},
    ct:log("Sending packet: ~p", [Encoded]),
    ok = gen_udp:send(Socket, Address, Port, Encoded),
    Foo = gen_udp:recv(Socket, 0, 3000),
    ct:log("Foo: ~p", [Foo]),
    ok.

%% internal functions

start_server() ->
    lists:foreach(fun radius_dict:add/1, radius_dict_file:load("dictionary")),
    lists:foreach(fun radius_dict:add/1, radius_dict_file:load("dictionary.nokia")),
    Nas1 = #nas_spec{name = nas1, ip = {127,0,0,1}, secret = ?SHARED_SECRET},
    Nas2 = #nas_spec{name = nas2, ip = {10,10,0,1}, secret = ?SHARED_SECRET},
    ServiceOpts = [
        {ip, {0,0,0,0}},
        {port, 1812},
        {callback, ?MODULE}
    ],
    radius:start_service(?MODULE, ServiceOpts),
    radius:add_client(?MODULE, Nas1),
    radius:add_client(?MODULE, Nas2).

stop_server() ->
    radius:stop_service(?MODULE).

handle_request(Type, Request, Client) ->
    io:format("~p", [{Type, Request, Client}]),
    noreply.

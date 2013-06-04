REBAR = ./rebar

all: compile

compile:
	@$(REBAR) compile

clean:
	@$(REBAR) clean

test: compile
	@$(REBAR) eunit xref skip_deps=true

dev: compile
	erl -pa ebin -pa deps/*/ebin -boot start_sasl -s radius -sname radius_dev


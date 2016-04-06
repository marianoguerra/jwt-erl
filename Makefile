PROJECT = jwt
DEPS = jsx base64url

dep_jsx = git https://github.com/talentdeficit/jsx.git v2.8.0
dep_base64url = git https://github.com/dvv/base64url.git v1.0

include erlang.mk

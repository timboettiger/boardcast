# --- Build stage ---
FROM alpine:3.20 AS build
RUN apk add --no-cache build-base make
WORKDIR /src
COPY . .
RUN make && install -D -m755 boardcast /out/boardcast

# --- Runtime stage ---
FROM alpine:3.20
# For hub: expose TCP (Hub port) + UDP discovery
EXPOSE 33654/tcp 53701/udp
COPY --from=build /out/boardcast /usr/local/bin/boardcast

# role=hub|leaf (default: hub)
ARG ROLE=hub
ENV ROLE=${ROLE}

# HUB (with cast) vs LEAF (discovery)
ENTRYPOINT ["/bin/sh","-lc"]
CMD [ "if [ \"$ROLE\" = \"leaf\" ]; then exec /usr/local/bin/boardcast leaf; else exec /usr/local/bin/boardcast --cast hub://0.0.0.0:33654; fi" ]

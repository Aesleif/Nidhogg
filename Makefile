-include .env

BINARY_SERVER  = nidhogg-server
BUILD_DIR      = bin
GOOS          ?= linux
GOARCH        ?= amd64

SSH_HOST      ?=
SSH_USER      ?= root
SSH_KEY       ?=
SSH_PASS      ?=
SSH_PORT      ?= 22
REMOTE_DIR    ?= /opt/nidhogg

ifdef SSH_PASS
  SSH_CMD = sshpass -p '$(SSH_PASS)' ssh -p $(SSH_PORT)
  SCP_CMD = sshpass -p '$(SSH_PASS)' scp -P $(SSH_PORT)
else
  SSH_CMD = ssh -i $(SSH_KEY) -p $(SSH_PORT)
  SCP_CMD = scp -i $(SSH_KEY) -P $(SSH_PORT)
endif

.PHONY: build test deploy deploy-config deploy-all ssh restart logs clean

build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(BUILD_DIR)/$(BINARY_SERVER) ./cmd/nidhogg-server

test:
	go test ./...

deploy: build
	$(SSH_CMD) $(SSH_USER)@$(SSH_HOST) "echo '$(SSH_PASS)' | sudo -S mkdir -p $(REMOTE_DIR) && echo '$(SSH_PASS)' | sudo -S chown $(SSH_USER) $(REMOTE_DIR)"
	$(SCP_CMD) $(BUILD_DIR)/$(BINARY_SERVER) $(SSH_USER)@$(SSH_HOST):$(REMOTE_DIR)/$(BINARY_SERVER)

deploy-config:
	$(SCP_CMD) env/server-config.json $(SSH_USER)@$(SSH_HOST):$(REMOTE_DIR)/server-config.json

deploy-all: deploy deploy-config

ssh:
	$(SSH_CMD) $(SSH_USER)@$(SSH_HOST)

restart:
	$(SSH_CMD) $(SSH_USER)@$(SSH_HOST) "systemctl restart $(BINARY_SERVER)"

logs:
	$(SSH_CMD) $(SSH_USER)@$(SSH_HOST) "journalctl -u $(BINARY_SERVER) -f"

clean:
	rm -rf $(BUILD_DIR)

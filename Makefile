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

SERVICE_NAME   = nidhogg-server
SERVICE_FILE   = /etc/systemd/system/$(SERVICE_NAME).service
CONFIG_FILE    = $(REMOTE_DIR)/server-config.json

.PHONY: build test deploy deploy-config deploy-all ssh restart logs clean install uninstall

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
	$(SSH_CMD) $(SSH_USER)@$(SSH_HOST) "echo '$(SSH_PASS)' | sudo -S systemctl restart $(SERVICE_NAME)"

logs:
	$(SSH_CMD) $(SSH_USER)@$(SSH_HOST) "echo '$(SSH_PASS)' | sudo -S journalctl -u $(SERVICE_NAME) -f"

define SERVICE_UNIT
[Unit]\nDescription=Nidhogg Server\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=$(REMOTE_DIR)/$(BINARY_SERVER) -config $(CONFIG_FILE)\nRestart=on-failure\nRestartSec=5\nLimitNOFILE=65536\n\n[Install]\nWantedBy=multi-user.target
endef

install: deploy deploy-config
	$(SSH_CMD) $(SSH_USER)@$(SSH_HOST) "\
		echo '$(SSH_PASS)' | sudo -S sh -c 'printf \"$(SERVICE_UNIT)\" > $(SERVICE_FILE)' && \
		echo '$(SSH_PASS)' | sudo -S systemctl daemon-reload && \
		echo '$(SSH_PASS)' | sudo -S systemctl enable $(SERVICE_NAME) && \
		echo '$(SSH_PASS)' | sudo -S systemctl start $(SERVICE_NAME)"

uninstall:
	$(SSH_CMD) $(SSH_USER)@$(SSH_HOST) "\
		echo '$(SSH_PASS)' | sudo -S systemctl stop $(SERVICE_NAME) || true; \
		echo '$(SSH_PASS)' | sudo -S systemctl disable $(SERVICE_NAME) || true; \
		echo '$(SSH_PASS)' | sudo -S rm -f $(SERVICE_FILE); \
		echo '$(SSH_PASS)' | sudo -S systemctl daemon-reload; \
		echo '$(SSH_PASS)' | sudo -S rm -rf $(REMOTE_DIR)"

clean:
	rm -rf $(BUILD_DIR)

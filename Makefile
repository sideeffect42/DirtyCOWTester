SRC_DIR := ./src
BUILD_DIR ?= ./build
BIN_DIR := ./bin

TARGET_EXEC ?= $(BIN_DIR)/dct
TESTER_FILE := /tmp/dirtycow_test

SRCS := $(shell find $(SRC_DIR) -iname '*.c')
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

DEBUG ?= 0

CFLAGS = -Wall -D__DEBUG__=$(DEBUG)
CPPFLAGS = -MMD -MP
LDFLAGS = -pthread

.PHONY: all test clean

all: $(TARGET_EXEC) ;

-include $(DEPS)

%/:
	mkdir -p "$*"

# c sources
.SECONDEXPANSION:
$(BUILD_DIR)/%.c.o: %.c | $$(@D)/
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$<" -o "$@"

.SECONDEXPANSION:
$(TARGET_EXEC): $(OBJS) | $$(@D)/
	$(CC) $(OBJS) -o "$@" $(LDFLAGS)

$(TESTER_FILE):
#	[ ! -d "$(dir $@)" ] && return 1
	touch "$@"
	echo '____________' > "$@"
	chmod 0404 "$@"
	su -c "chown 0:0 \"$@\""

test: $(TARGET_EXEC) $(TESTER_FILE)
	"$(TARGET_EXEC)"
	su -c "rm \"$(TESTER_FILE)\""

clean:
	-$(RM) -r "$(BUILD_DIR)"
	-$(RM) "$(TARGET_EXEC)"

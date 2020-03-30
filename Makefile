CFLAGS +=  -O0

SOURCE  = $(wildcard spectre*.c)
PROGRAM = $(SOURCE:.c=.out)
     
all: $(PROGRAM)

GIT_SHELL_EXIT := $(shell git status --porcelain 2> /dev/null >&2 ; echo $$?)

# It can be non-zero when not in git repository or git is not installed.
# It can happen when downloaded using github's "Download ZIP" option.
ifeq ($(GIT_SHELL_EXIT),0)
# Check if working dir is clean.
GIT_STATUS := $(shell git status --porcelain)
ifndef GIT_STATUS
GIT_COMMIT_HASH := $(shell git rev-parse HEAD)
CFLAGS += -DGIT_COMMIT_HASH='"$(GIT_COMMIT_HASH)"'
endif
endif
COLORS ?= 1
CFLAGS += -DCOLORS=$(COLORS)
     
%.out: %.c ; $(CC) $(CFLAGS) -o $@ $<
     
clean: ; rm -f *.out

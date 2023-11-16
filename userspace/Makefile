# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS := user_dtn
MY_TARGETS := myclient
MYBINN_TARGETS := mybinncli
MYBINN_SERV_TARGETS := sim_server

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/
FACILIO_DIR = ../facil_io_7.0/

# Extend with another COMMON_OBJS
COMMON_OBJS += $(COMMON_DIR)/common_libbpf.o

OTHER_OBJS = ./user_assess.o
OTHER_OBJS += ./wrapsomeunix.o
MY_OBJS = ./wrapsomeunix.o

FACILIO_OBJS += $(FACILIO_DIR)/lib/facil/fio.o
FACILIO_OBJS += $(FACILIO_DIR)/lib/facil/fiobj/fiobj_hash.o
FACILIO_OBJS += $(FACILIO_DIR)/lib/facil/fiobj/fiobj_ary.o
FACILIO_OBJS += $(FACILIO_DIR)/lib/facil/fiobj/fiobj_numbers.o
FACILIO_OBJS += $(FACILIO_DIR)/lib/facil/fiobj/fiobj_str.o
FACILIO_OBJS += $(FACILIO_DIR)/lib/facil/fiobj/fiobj_data.o
FACILIO_OBJS += $(FACILIO_DIR)/lib/facil/fiobj/fiobj_json.o
FACILIO_OBJS += $(FACILIO_DIR)/lib/facil/fiobj/fiobject.o
FACILIO_OBJS += $(FACILIO_DIR)/lib/facil/http/http.o
FACILIO_OBJS += $(FACILIO_DIR)/lib/facil/http/http_internal.o
FACILIO_OBJS += $(FACILIO_DIR)/lib/facil/http/http1.o
FACILIO_OBJS += $(FACILIO_DIR)/lib/facil/http/websockets.o
FACILIO_OBJS += $(FACILIO_DIR)/lib/facil/http/parsers/http1_parser.o

include $(COMMON_DIR)/common.mk

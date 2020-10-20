#pragma once
/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh & Dang Hoang Vu, 2015 */

/* Sample code to demonstrate how to emulate X86 code */

//#include <capstone/platform.h>
//#include <capstone/capstone.h>
//
//#include <unicorn/unicorn.h>

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "unicorn/platform.h"
#include <signal.h>

#include "x86_64.h"
#include "qemu/host-utils.h"
#include "cpu.h"
#include "tcg-op.h"
#include "exec/cpu_ldst.h"

#include "exec/helper-proto.h"
#include "exec/helper-gen.h"

#include "uc_priv.h"
#include "trans.h"

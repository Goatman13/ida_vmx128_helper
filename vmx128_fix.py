# Author: kozarovv
# Using parts of code from ida-emotionengine.py by oct0xor

import idaapi
import ida_ida
import ida_allins
import ida_idp
import ida_bytes
import ida_ua

ITYPE_START = ida_idp.CUSTOM_INSN_ITYPE + 0x100
MNEM_WIDTH = 10

kVX128   = 1
kVX128_2 = 2
kVX128_5 = 3
kVX128_R = 4

class vmx128_disassemble(idaapi.IDP_Hooks):

	def __init__(self):
		idaapi.IDP_Hooks.__init__(self)

		class idef:
			def __init__(self, opcode, name, typ, cmt):
				self.opcode = opcode
				self.name = name
				self.typ = typ
				self.cmt = cmt

		self.itable = [
			# Coprocessor Calculation Instructions
			idef(0x14000010, "vaddfp128"   , kVX128  , ""),
			idef(0x14000210, "vand128"     , kVX128  , ""),
			idef(0x14000250, "vandc128"    , kVX128  , ""),
			idef(0x14000110, "vmaddcfp128" , kVX128  , ""),
			idef(0x140000d0, "vmaddfp128"  , kVX128  , ""),
			idef(0x18000280, "vmaxfp128"   , kVX128  , ""),
			idef(0x180002c0, "vminfp128"   , kVX128  , ""),
			idef(0x18000300, "vmrghw128"   , kVX128  , ""),
			idef(0x18000340, "vmrglw128"   , kVX128  , ""),
			idef(0x14000190, "vmsum3fp128" , kVX128  , ""),
			idef(0x140001d0, "vmsum4fp128" , kVX128  , ""),
			idef(0x14000090, "vmulfp128"   , kVX128  , ""),
			idef(0x14000150, "vnmsubfp128" , kVX128  , ""),
			idef(0x14000290, "vnor128"     , kVX128  , ""),
			idef(0x140002d0, "vor128"      , kVX128  , ""),
			idef(0x14000200, "vpkshss128"  , kVX128  , ""),
			idef(0x14000240, "vpkshus128"  , kVX128  , ""),
			idef(0x14000280, "vpkswss128"  , kVX128  , ""),
			idef(0x140002c0, "vpkswus128"  , kVX128  , ""),
			idef(0x14000300, "vpkuhum128"  , kVX128  , ""),
			idef(0x14000340, "vpkuhus128"  , kVX128  , ""),
			idef(0x14000380, "vpkuwum128"  , kVX128  , ""),
			idef(0x140003c0, "vpkuwus128"  , kVX128  , ""),
			idef(0x18000050, "vrlw128"     , kVX128  , ""),
			idef(0x14000350, "vsel128"     , kVX128  , ""),
			idef(0x14000390, "vslo128"     , kVX128  , ""),
			idef(0x180000d0, "vslw128"     , kVX128  , ""),
			idef(0x18000150, "vsraw128"    , kVX128  , ""),
			idef(0x140003d0, "vsro128"     , kVX128  , ""),
			idef(0x180001d0, "vsrw128"     , kVX128  , ""),
			idef(0x14000050, "vsubfp128"   , kVX128  , ""),
			idef(0x18000380, "vupkhsb128"  , kVX128  , ""),
			idef(0x180003c0, "vupklsb128"  , kVX128  , ""),
			idef(0x14000310, "vxor128"     , kVX128  , ""),
			idef(0x14000000, "vperm128"    , kVX128_2, ""),
			idef(0x10000010, "vsldoi128"   , kVX128_5, ""),
			idef(0x18000180, "vcmpbfp128"  , kVX128_R, ""),
			idef(0x18000000, "vcmpeqfp128" , kVX128_R, ""),
			idef(0x18000200, "vcmpequw128" , kVX128_R, ""),
			idef(0x18000080, "vcmpgefp128" , kVX128_R, ""),
			idef(0x18000100, "vcmpgtfp128" , kVX128_R, ""),
		]

		self.VF_REG = 1

		self.reg_types = {
			1:  [self.VF_REG, self.VF_REG, self.VF_REG],
			2:  [self.VF_REG, self.VF_REG, self.VF_REG, self.VF_REG],
			3:  [self.VF_REG, self.VF_REG, self.VF_REG],
			4:  [self.VF_REG, self.VF_REG, self.VF_REG],
		}

		self.itable.sort(key=lambda x: x.opcode)

		for entry in self.itable:
			entry.name = entry.name.lower()

	def set_regs_1(self, insn, a, b, c):
		insn.Op1.type = ida_ua.o_idpspec1
		insn.Op1.reg = a
		insn.Op2.type = ida_ua.o_idpspec1
		insn.Op2.reg = b
		insn.Op3.type = ida_ua.o_idpspec1
		insn.Op3.reg = c

	def set_regs_2(self, insn, a, b, c, d):
		insn.Op1.type = ida_ua.o_idpspec1
		insn.Op1.reg = a
		insn.Op2.type = ida_ua.o_idpspec1
		insn.Op2.reg = b
		insn.Op3.type = ida_ua.o_idpspec1
		insn.Op3.reg = c
		insn.Op4.type = ida_ua.o_idpspec1
		insn.Op4.reg = d

	def set_regs_3(self, insn, a, b, c, imm):
		insn.Op1.type = ida_ua.o_idpspec1
		insn.Op1.reg = a
		insn.Op2.type = ida_ua.o_idpspec1
		insn.Op2.reg = b
		insn.Op3.type = ida_ua.o_idpspec1
		insn.Op3.reg = c
		insn.Op4.type = ida_ua.o_imm
		insn.Op4.value = imm

	def decode_type_1(self, insn, dword):
		vmxA    = (dword >> 16) & 0x1F | dword & 0x20 | (dword >> 4) & 0x40
		vmxB    = (dword >> 11) & 0x1F | (dword << 5) & 0x60
		vmxD    = (dword >> 21) & 0x1F | (dword << 3) & 0x60
		self.set_regs_1(insn, vmxD, vmxA, vmxB)

	def decode_type_2(self, insn, dword):
		vmxA    = (dword >> 16) & 0x1F | dword & 0x20 | (dword >> 4) & 0x40
		vmxB    = (dword >> 11) & 0x1F | (dword << 5) & 0x60
		vmxD    = (dword >> 21) & 0x1F | (dword << 3) & 0x60
		vmxC    = (dword >> 6)  & 0x7
		self.set_regs_2(insn, vmxD, vmxA, vmxB, vmxC)

	def decode_type_3(self, insn, dword):
		vmxA    = (dword >> 16) & 0x1F | dword & 0x20 | (dword >> 4) & 0x40
		vmxB    = (dword >> 11) & 0x1F | (dword << 5) & 0x60
		vmxD    = (dword >> 21) & 0x1F | (dword << 3) & 0x60
		vmxShb  = (dword >> 6)  & 0xF
		self.set_regs_3(insn, vmxD, vmxA, vmxB, vmxShb)

	def decode_type_4(self, insn, dword):
		vmxA    = (dword >> 16) & 0x1F | dword & 0x20 | (dword >> 4) & 0x40
		vmxB    = (dword >> 11) & 0x1F | (dword << 5) & 0x60
		vmxD    = (dword >> 21) & 0x1F | (dword << 3) & 0x60
		self.set_regs_1(insn, vmxD, vmxA, vmxB)

	def set_reg_type(self, op, reg_type):
		op.specval = reg_type

	def decode_instruction(self, index, insn, dword):

		insn.itype = ITYPE_START + index

		decoder = getattr(self, 'decode_type_%d' % self.itable[index].typ)
		decoder(insn, dword)

		regs = self.reg_types[self.itable[index].typ]


		if (len(regs) == 3):
			self.set_reg_type(insn.Op1, regs[0])
			self.set_reg_type(insn.Op2, regs[1])
			self.set_reg_type(insn.Op3, regs[2])

		elif (len(regs) == 4):
			self.set_reg_type(insn.Op1, regs[0])
			self.set_reg_type(insn.Op2, regs[1])
			self.set_reg_type(insn.Op3, regs[2])
			self.set_reg_type(insn.Op4, regs[3])

		insn.size = 4

	def ev_ana_insn(self, insn):

		dword = ida_bytes.get_wide_dword(insn.ea)
		opcode = dword & 0xFC0003D0
		opcode_t = opcode & ~0x40
		opcode_h = (opcode >> 26 & 0x3F)
		if opcode_h == 5 and opcode & 0x210 == 0:
			opcode = 0x14000000
		elif opcode_h == 4 and opcode & 0x10 == 1:
			opcode = 0x10000010
		elif opcode_h == 6:
			if opcode_t == 0x18000000 or opcode_t == 0x18000080 or opcode_t == 0x18000100 or opcode_t == 0x18000180 or opcode_t == 0x18000200:
				opcode = opcode_t
		found = False
		index = 0
		pos = 0
		for i in range(pos, len(self.itable)):
			if (self.itable[i].opcode == opcode):
				found = True
				index = i
				break

		if (not found):
			return 0

		self.decode_instruction(index, insn, dword)

		return insn.size

	def ev_get_autocmt(self, insn):
		if (insn.itype >= ITYPE_START and insn.itype < ITYPE_START + len(self.itable)):
			return self.itable[insn.itype-ITYPE_START].cmt
		return 0

	def ev_emu_insn(self, insn):
		if (insn.itype >= ITYPE_START and insn.itype < ITYPE_START + len(self.itable)):
			#print(self.itable[insn.itype-ITYPE_START].cmt)
			insn.add_cref(insn.ea + insn.size, 0, 21); # 21 Ordinary flow
			return 1
		return 0

	def get_register(self, op, ctx):

		if (op.specval == self.VF_REG):
			return "v%d" % op.reg

	def ev_out_operand(self, ctx, op):

		if (ctx.insn.itype >= ITYPE_START and ctx.insn.itype < ITYPE_START + len(self.itable)):
			ctx.out_register(self.get_register(op, ctx))
			return 1
		return 0

	def ev_out_mnem(self, ctx):
		if (ctx.insn.itype >= ITYPE_START and ctx.insn.itype < ITYPE_START + len(self.itable)):

			dot = ""
			if (self.itable[ctx.insn.itype - ITYPE_START].typ == kVX128_R) and ida_bytes.get_wide_dword(ctx.insn.ea) & 0x40 == 0x40:
				dot = "."

			ctx.out_custom_mnem(self.itable[ctx.insn.itype - ITYPE_START].name, MNEM_WIDTH, dot)
			return 1
		return 0

class vmx128_plugin_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_HIDE
	comment = ""
	help = ""
	wanted_name = "vmx128 instructions disassembler"
	wanted_hotkey = ""

	def __init__(self):
		self.vmx128 = None

	def init(self):
		
		if idaapi.ph.id == idaapi.PLFM_PPC:
			self.vmx128 = vmx128_disassemble()
			self.vmx128.hook()
			print("vmx128 instructions disassembler is loaded")
			return idaapi.PLUGIN_KEEP

		return idaapi.PLUGIN_SKIP

	def run(self, arg):
		pass

	def term(self):
		if (self.vmx128 != None):
			self.vmx128.unhook()
			self.vmx128 = None

def PLUGIN_ENTRY():
	return vmx128_plugin_t()

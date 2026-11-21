// AArch64 code with data among it, for tests/arm64_data_in_code.rs. Each section is one case.
// `.word` is data, which `$d` marks; `.inst` is a word of data that nothing marks.

// A zero-length data directive among code: `$d` and `$x` at one address.
	.section .text.mid, "ax"
	.globl mid
	.type mid, %function
mid:
	stp x29, x30, [sp, #-16]!
	.space 0
	bl mid_helper
	ldp x29, x30, [sp], #16
	ret
mid_helper:
	add x0, x0, #1
	ret

// The same at a section's start.
	.section .text.start, "ax"
	.space 0
	.globl start
	.type start, %function
start:
	stp x29, x30, [sp, #-16]!
	bl start_helper
	ldp x29, x30, [sp], #16
	ret
start_helper:
	add x0, x0, #2
	ret

// The same at a section's end, where the next section starts with code.
	.section .text.end, "ax"
	.globl end
	.type end, %function
end:
	stp x29, x30, [sp, #-16]!
	bl end_helper
	ldp x29, x30, [sp], #16
	ret
	.space 0

	.section .text.after, "ax"
end_helper:
	add x0, x0, #3
	ret

// Data at a section's start, right where the section before ends: a word that reads as `bl` to
// the `ret` of the function after it.
	.section .text.hashed, "ax"
	.word 0x94000002
	.globl hashed
	.type hashed, %function
hashed:
	mov x0, xzr
	ret

// A kernel warning traps and goes on, so the jump back after `brk` runs, and only the trap
// reaches it. Right after it is the next function's kCFI hash. The branches into the cold blocks
// pass another function's start, so each reads as a tail call, as recore reads those of a long
// function in mali_kbase.ko.
	.section .text.warn, "ax"
	.globl warn
	.type warn, %function
warn:
	stp x29, x30, [sp, #-16]!
	cbz x0, warn_split
	cbz x1, warn_cold
	bl other
	ldp x29, x30, [sp], #16
	ret
	.globl between
	.type between, %function
between:
	ret
warn_split:
	mov w0, #-22
1:	ldp x29, x30, [sp], #16
	ret
warn_cold:
	mov w0, wzr
	brk #0x800
	b 1b
	.word 0xd74eb087
	.globl after_warn
	.type after_warn, %function
after_warn:
	ret

// A kCFI hash with no `$d`, as in a stripped module, after a call that may not return. It reads
// as `adr x16, jumps+0xe`, where no instruction starts, between
// `cbnz` and the block it branches to.
	.section .text.unmarked, "ax"
	.globl jumps
	.type jumps, %function
jumps:
	cbnz x1, jumps_fail
	cbz x0, 2f
	b 1f
2:	mov x0, #1
	mov x0, #2
1:	ret
jumps_fail:
	bl fail
	.inst 0x50ffff90
	.globl after_jumps
	.type after_jumps, %function
after_jumps:
	ret

// Data at a section's end, with no mark after it: two words that read as `bl tail+8; ret`.
	.section .text.tail, "ax"
	.globl tail
	.type tail, %function
tail:
	mov x0, xzr
	ret
	add x0, x0, #4
	ret
	.word 0x97fffffe
	.word 0xd65f03c0

// Marks placed past their own section's end, over the call in the section after it.
	.section .text.stray, "ax"
	.globl stray
	.type stray, %function
stray:
	mov x0, xzr
	ret
	.set "$d.stray", stray + 0x10
	.set "$x.stray", stray + 0x20

	.section .text.strayed, "ax"
	.globl strayed
	.type strayed, %function
strayed:
	stp x29, x30, [sp, #-16]!
	mov x0, xzr
	bl strayed_helper
	ldp x29, x30, [sp], #16
	ret
strayed_helper:
	add x0, x0, #5
	ret

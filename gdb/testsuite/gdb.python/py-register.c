/* So we have a data section */
const char foo[] = "somestring";

asm("\
.section .text\n\
.global text_msym\n\
text_msym:\n\
	.byte 0\n\
.section .data\n\
.globl data_msym\n\
data_msym:\n\
	.asciz \"minsym text\"\n\
");

int
main(void)
{
	return 0;
}

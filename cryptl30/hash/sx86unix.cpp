/* Run the C pre-processor over this file with one of the following defined
 * ELF - elf object files,
 * OUT - a.out object files,
 * BSDI - BSDI style a.out object files
 * SOL - Solaris style elf
 */

#define TYPE(a,b)       .type   a,b
#define SIZE(a,b)       .size   a,b

#if defined(OUT) || defined(BSDI)

#endif

#ifdef OUT
#define OK	1
#define ALIGN	4
#endif

#ifdef BSDI
#define OK              1
#define ALIGN           4
#undef SIZE
#undef TYPE
#endif

#if defined(ELF) || defined(SOL)
#define OK              1
#define ALIGN           16
#endif

#ifndef OK
You need to define one of
ELF - elf systems - linux-elf, NetBSD and DG-UX
OUT - a.out systems - linux-a.out and FreeBSD
SOL - solaris systems, which are elf with strange comment lines
BSDI - a.out with a very primative version of as.
#endif

/* Let the Assembler begin :-) */
	/* Don't even think of reading this code */
	/* It was automatically generated by sha1-586.pl */
	/* Which is a perl program used to generate the x86 assember for */
	/* any of elf, a.out, BSDI,Win32, or Solaris */
	/* eric <eay@cryptsoft.com> */

	.file	"sha1-586.s"
	.version	"01.01"
gcc2_compiled.:
.text
	.align ALIGN
.globl sha1_block_x86
	TYPE(sha1_block_x86,@function)
sha1_block_x86:
	pushl	%esi
	pushl	%ebp
	movl	20(%esp),	%eax
	movl	16(%esp),	%esi
	addl	%esi,		%eax
	movl	12(%esp),	%ebp
	pushl	%ebx
	subl	$64,		%eax
	pushl	%edi
	movl	4(%ebp),	%ebx
	subl	$72,		%esp
	movl	12(%ebp),	%edx
	movl	16(%ebp),	%edi
	movl	8(%ebp),	%ecx
	movl	%eax,		68(%esp)
	/* First we need to setup the X array */
	movl	(%esi),		%eax
.L000start:
	/* First, load the words onto the stack in network byte order */
	bswapl	%eax
	movl	%eax,		(%esp)
	movl	4(%esi),	%eax
	bswapl	%eax
	movl	%eax,		4(%esp)
	movl	8(%esi),	%eax
	bswapl	%eax
	movl	%eax,		8(%esp)
	movl	12(%esi),	%eax
	bswapl	%eax
	movl	%eax,		12(%esp)
	movl	16(%esi),	%eax
	bswapl	%eax
	movl	%eax,		16(%esp)
	movl	20(%esi),	%eax
	bswapl	%eax
	movl	%eax,		20(%esp)
	movl	24(%esi),	%eax
	bswapl	%eax
	movl	%eax,		24(%esp)
	movl	28(%esi),	%eax
	bswapl	%eax
	movl	%eax,		28(%esp)
	movl	32(%esi),	%eax
	bswapl	%eax
	movl	%eax,		32(%esp)
	movl	36(%esi),	%eax
	bswapl	%eax
	movl	%eax,		36(%esp)
	movl	40(%esi),	%eax
	bswapl	%eax
	movl	%eax,		40(%esp)
	movl	44(%esi),	%eax
	bswapl	%eax
	movl	%eax,		44(%esp)
	movl	48(%esi),	%eax
	bswapl	%eax
	movl	%eax,		48(%esp)
	movl	52(%esi),	%eax
	bswapl	%eax
	movl	%eax,		52(%esp)
	movl	56(%esi),	%eax
	bswapl	%eax
	movl	%eax,		56(%esp)
	movl	60(%esi),	%eax
	bswapl	%eax
	movl	%eax,		60(%esp)
	/* We now have the X array on the stack */
	/* starting at sp-4 */
	movl	%esi,		64(%esp)

	/* Start processing */
	movl	(%ebp),		%eax
	/* 00_15 0 */
	movl	%ecx,		%esi
	movl	%eax,		%ebp
	xorl	%edx,		%esi
	roll	$5,		%ebp
	andl	%ebx,		%esi
	addl	%edi,		%ebp
.byte 209
.byte 203		/* rorl $1 %ebx */
	movl	(%esp),		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	xorl	%edx,		%esi
	leal	1518500249(%ebp,%edi,1),%ebp
	movl	%ebx,		%edi
	addl	%ebp,		%esi
	xorl	%ecx,		%edi
	movl	%esi,		%ebp
	andl	%eax,		%edi
	roll	$5,		%ebp
	addl	%edx,		%ebp
	movl	4(%esp),	%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	xorl	%ecx,		%edi
.byte 209
.byte 200		/* rorl $1 %eax */
	leal	1518500249(%ebp,%edx,1),%ebp
	addl	%ebp,		%edi
	/* 00_15 2 */
	movl	%eax,		%edx
	movl	%edi,		%ebp
	xorl	%ebx,		%edx
	roll	$5,		%ebp
	andl	%esi,		%edx
	addl	%ecx,		%ebp
.byte 209
.byte 206		/* rorl $1 %esi */
	movl	8(%esp),	%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	xorl	%ebx,		%edx
	leal	1518500249(%ebp,%ecx,1),%ebp
	movl	%esi,		%ecx
	addl	%ebp,		%edx
	xorl	%eax,		%ecx
	movl	%edx,		%ebp
	andl	%edi,		%ecx
	roll	$5,		%ebp
	addl	%ebx,		%ebp
	movl	12(%esp),	%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	xorl	%eax,		%ecx
.byte 209
.byte 207		/* rorl $1 %edi */
	leal	1518500249(%ebp,%ebx,1),%ebp
	addl	%ebp,		%ecx
	/* 00_15 4 */
	movl	%edi,		%ebx
	movl	%ecx,		%ebp
	xorl	%esi,		%ebx
	roll	$5,		%ebp
	andl	%edx,		%ebx
	addl	%eax,		%ebp
.byte 209
.byte 202		/* rorl $1 %edx */
	movl	16(%esp),	%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	xorl	%esi,		%ebx
	leal	1518500249(%ebp,%eax,1),%ebp
	movl	%edx,		%eax
	addl	%ebp,		%ebx
	xorl	%edi,		%eax
	movl	%ebx,		%ebp
	andl	%ecx,		%eax
	roll	$5,		%ebp
	addl	%esi,		%ebp
	movl	20(%esp),	%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	xorl	%edi,		%eax
.byte 209
.byte 201		/* rorl $1 %ecx */
	leal	1518500249(%ebp,%esi,1),%ebp
	addl	%ebp,		%eax
	/* 00_15 6 */
	movl	%ecx,		%esi
	movl	%eax,		%ebp
	xorl	%edx,		%esi
	roll	$5,		%ebp
	andl	%ebx,		%esi
	addl	%edi,		%ebp
.byte 209
.byte 203		/* rorl $1 %ebx */
	movl	24(%esp),	%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	xorl	%edx,		%esi
	leal	1518500249(%ebp,%edi,1),%ebp
	movl	%ebx,		%edi
	addl	%ebp,		%esi
	xorl	%ecx,		%edi
	movl	%esi,		%ebp
	andl	%eax,		%edi
	roll	$5,		%ebp
	addl	%edx,		%ebp
	movl	28(%esp),	%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	xorl	%ecx,		%edi
.byte 209
.byte 200		/* rorl $1 %eax */
	leal	1518500249(%ebp,%edx,1),%ebp
	addl	%ebp,		%edi
	/* 00_15 8 */
	movl	%eax,		%edx
	movl	%edi,		%ebp
	xorl	%ebx,		%edx
	roll	$5,		%ebp
	andl	%esi,		%edx
	addl	%ecx,		%ebp
.byte 209
.byte 206		/* rorl $1 %esi */
	movl	32(%esp),	%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	xorl	%ebx,		%edx
	leal	1518500249(%ebp,%ecx,1),%ebp
	movl	%esi,		%ecx
	addl	%ebp,		%edx
	xorl	%eax,		%ecx
	movl	%edx,		%ebp
	andl	%edi,		%ecx
	roll	$5,		%ebp
	addl	%ebx,		%ebp
	movl	36(%esp),	%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	xorl	%eax,		%ecx
.byte 209
.byte 207		/* rorl $1 %edi */
	leal	1518500249(%ebp,%ebx,1),%ebp
	addl	%ebp,		%ecx
	/* 00_15 10 */
	movl	%edi,		%ebx
	movl	%ecx,		%ebp
	xorl	%esi,		%ebx
	roll	$5,		%ebp
	andl	%edx,		%ebx
	addl	%eax,		%ebp
.byte 209
.byte 202		/* rorl $1 %edx */
	movl	40(%esp),	%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	xorl	%esi,		%ebx
	leal	1518500249(%ebp,%eax,1),%ebp
	movl	%edx,		%eax
	addl	%ebp,		%ebx
	xorl	%edi,		%eax
	movl	%ebx,		%ebp
	andl	%ecx,		%eax
	roll	$5,		%ebp
	addl	%esi,		%ebp
	movl	44(%esp),	%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	xorl	%edi,		%eax
.byte 209
.byte 201		/* rorl $1 %ecx */
	leal	1518500249(%ebp,%esi,1),%ebp
	addl	%ebp,		%eax
	/* 00_15 12 */
	movl	%ecx,		%esi
	movl	%eax,		%ebp
	xorl	%edx,		%esi
	roll	$5,		%ebp
	andl	%ebx,		%esi
	addl	%edi,		%ebp
.byte 209
.byte 203		/* rorl $1 %ebx */
	movl	48(%esp),	%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	xorl	%edx,		%esi
	leal	1518500249(%ebp,%edi,1),%ebp
	movl	%ebx,		%edi
	addl	%ebp,		%esi
	xorl	%ecx,		%edi
	movl	%esi,		%ebp
	andl	%eax,		%edi
	roll	$5,		%ebp
	addl	%edx,		%ebp
	movl	52(%esp),	%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	xorl	%ecx,		%edi
.byte 209
.byte 200		/* rorl $1 %eax */
	leal	1518500249(%ebp,%edx,1),%ebp
	addl	%ebp,		%edi
	/* 00_15 14 */
	movl	%eax,		%edx
	movl	%edi,		%ebp
	xorl	%ebx,		%edx
	roll	$5,		%ebp
	andl	%esi,		%edx
	addl	%ecx,		%ebp
.byte 209
.byte 206		/* rorl $1 %esi */
	movl	56(%esp),	%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	xorl	%ebx,		%edx
	leal	1518500249(%ebp,%ecx,1),%ebp
	movl	%esi,		%ecx
	addl	%ebp,		%edx
	xorl	%eax,		%ecx
	movl	%edx,		%ebp
	andl	%edi,		%ecx
	roll	$5,		%ebp
	addl	%ebx,		%ebp
	movl	60(%esp),	%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	xorl	%eax,		%ecx
.byte 209
.byte 207		/* rorl $1 %edi */
	leal	1518500249(%ebp,%ebx,1),%ebp
	addl	%ebp,		%ecx
	/* 16_19 16 */
	nop
	movl	(%esp),		%ebp
	movl	8(%esp),	%ebx
	xorl	%ebp,		%ebx
	movl	32(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	52(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	%edi,		%ebp
.byte 209
.byte 195		/* roll $1 %ebx */
	xorl	%esi,		%ebp
	movl	%ebx,		(%esp)
	andl	%edx,		%ebp
	leal	1518500249(%ebx,%eax,1),%ebx
	xorl	%esi,		%ebp
	movl	%ecx,		%eax
	addl	%ebp,		%ebx
	roll	$5,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	addl	%eax,		%ebx
	movl	4(%esp),	%eax
	movl	12(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	36(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	56(%esp),	%ebp
.byte 209
.byte 202		/* rorl $1 %edx */
	xorl	%ebp,		%eax
.byte 209
.byte 192		/* roll $1 %eax */
	movl	%edx,		%ebp
	xorl	%edi,		%ebp
	movl	%eax,		4(%esp)
	andl	%ecx,		%ebp
	leal	1518500249(%eax,%esi,1),%eax
	xorl	%edi,		%ebp
	movl	%ebx,		%esi
	roll	$5,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%esi,		%eax
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%ebp,		%eax
	/* 16_19 18 */
	movl	8(%esp),	%ebp
	movl	16(%esp),	%esi
	xorl	%ebp,		%esi
	movl	40(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	60(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	%ecx,		%ebp
.byte 209
.byte 198		/* roll $1 %esi */
	xorl	%edx,		%ebp
	movl	%esi,		8(%esp)
	andl	%ebx,		%ebp
	leal	1518500249(%esi,%edi,1),%esi
	xorl	%edx,		%ebp
	movl	%eax,		%edi
	addl	%ebp,		%esi
	roll	$5,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	addl	%edi,		%esi
	movl	12(%esp),	%edi
	movl	20(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	44(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	(%esp),		%ebp
.byte 209
.byte 203		/* rorl $1 %ebx */
	xorl	%ebp,		%edi
.byte 209
.byte 199		/* roll $1 %edi */
	movl	%ebx,		%ebp
	xorl	%ecx,		%ebp
	movl	%edi,		12(%esp)
	andl	%eax,		%ebp
	leal	1518500249(%edi,%edx,1),%edi
	xorl	%ecx,		%ebp
	movl	%esi,		%edx
	roll	$5,		%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%edx,		%edi
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%ebp,		%edi
	/* 20_39 20 */
	movl	16(%esp),	%edx
	movl	24(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	48(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	4(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	%esi,		%ebp
.byte 209
.byte 194		/* roll $1 %edx */
	xorl	%eax,		%ebp
	movl	%edx,		16(%esp)
	xorl	%ebx,		%ebp
	leal	1859775393(%edx,%ecx,1),%edx
	movl	%edi,		%ecx
	roll	$5,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	addl	%ebp,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	addl	%ecx,		%edx
	/* 20_39 21 */
	movl	20(%esp),	%ecx
	movl	28(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	52(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	8(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	%edi,		%ebp
.byte 209
.byte 193		/* roll $1 %ecx */
	xorl	%esi,		%ebp
	movl	%ecx,		20(%esp)
	xorl	%eax,		%ebp
	leal	1859775393(%ecx,%ebx,1),%ecx
	movl	%edx,		%ebx
	roll	$5,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebp,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebx,		%ecx
	/* 20_39 22 */
	movl	24(%esp),	%ebx
	movl	32(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	56(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	12(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	%edx,		%ebp
.byte 209
.byte 195		/* roll $1 %ebx */
	xorl	%edi,		%ebp
	movl	%ebx,		24(%esp)
	xorl	%esi,		%ebp
	leal	1859775393(%ebx,%eax,1),%ebx
	movl	%ecx,		%eax
	roll	$5,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	addl	%ebp,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	addl	%eax,		%ebx
	/* 20_39 23 */
	movl	28(%esp),	%eax
	movl	36(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	60(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	16(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	%ecx,		%ebp
.byte 209
.byte 192		/* roll $1 %eax */
	xorl	%edx,		%ebp
	movl	%eax,		28(%esp)
	xorl	%edi,		%ebp
	leal	1859775393(%eax,%esi,1),%eax
	movl	%ebx,		%esi
	roll	$5,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%ebp,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%esi,		%eax
	/* 20_39 24 */
	movl	32(%esp),	%esi
	movl	40(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	(%esp),		%ebp
	xorl	%ebp,		%esi
	movl	20(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	%ebx,		%ebp
.byte 209
.byte 198		/* roll $1 %esi */
	xorl	%ecx,		%ebp
	movl	%esi,		32(%esp)
	xorl	%edx,		%ebp
	leal	1859775393(%esi,%edi,1),%esi
	movl	%eax,		%edi
	roll	$5,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	addl	%ebp,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	addl	%edi,		%esi
	/* 20_39 25 */
	movl	36(%esp),	%edi
	movl	44(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	4(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	24(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	%eax,		%ebp
.byte 209
.byte 199		/* roll $1 %edi */
	xorl	%ebx,		%ebp
	movl	%edi,		36(%esp)
	xorl	%ecx,		%ebp
	leal	1859775393(%edi,%edx,1),%edi
	movl	%esi,		%edx
	roll	$5,		%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%ebp,		%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%edx,		%edi
	/* 20_39 26 */
	movl	40(%esp),	%edx
	movl	48(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	8(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	28(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	%esi,		%ebp
.byte 209
.byte 194		/* roll $1 %edx */
	xorl	%eax,		%ebp
	movl	%edx,		40(%esp)
	xorl	%ebx,		%ebp
	leal	1859775393(%edx,%ecx,1),%edx
	movl	%edi,		%ecx
	roll	$5,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	addl	%ebp,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	addl	%ecx,		%edx
	/* 20_39 27 */
	movl	44(%esp),	%ecx
	movl	52(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	12(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	32(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	%edi,		%ebp
.byte 209
.byte 193		/* roll $1 %ecx */
	xorl	%esi,		%ebp
	movl	%ecx,		44(%esp)
	xorl	%eax,		%ebp
	leal	1859775393(%ecx,%ebx,1),%ecx
	movl	%edx,		%ebx
	roll	$5,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebp,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebx,		%ecx
	/* 20_39 28 */
	movl	48(%esp),	%ebx
	movl	56(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	16(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	36(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	%edx,		%ebp
.byte 209
.byte 195		/* roll $1 %ebx */
	xorl	%edi,		%ebp
	movl	%ebx,		48(%esp)
	xorl	%esi,		%ebp
	leal	1859775393(%ebx,%eax,1),%ebx
	movl	%ecx,		%eax
	roll	$5,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	addl	%ebp,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	addl	%eax,		%ebx
	/* 20_39 29 */
	movl	52(%esp),	%eax
	movl	60(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	20(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	40(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	%ecx,		%ebp
.byte 209
.byte 192		/* roll $1 %eax */
	xorl	%edx,		%ebp
	movl	%eax,		52(%esp)
	xorl	%edi,		%ebp
	leal	1859775393(%eax,%esi,1),%eax
	movl	%ebx,		%esi
	roll	$5,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%ebp,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%esi,		%eax
	/* 20_39 30 */
	movl	56(%esp),	%esi
	movl	(%esp),		%ebp
	xorl	%ebp,		%esi
	movl	24(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	44(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	%ebx,		%ebp
.byte 209
.byte 198		/* roll $1 %esi */
	xorl	%ecx,		%ebp
	movl	%esi,		56(%esp)
	xorl	%edx,		%ebp
	leal	1859775393(%esi,%edi,1),%esi
	movl	%eax,		%edi
	roll	$5,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	addl	%ebp,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	addl	%edi,		%esi
	/* 20_39 31 */
	movl	60(%esp),	%edi
	movl	4(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	28(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	48(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	%eax,		%ebp
.byte 209
.byte 199		/* roll $1 %edi */
	xorl	%ebx,		%ebp
	movl	%edi,		60(%esp)
	xorl	%ecx,		%ebp
	leal	1859775393(%edi,%edx,1),%edi
	movl	%esi,		%edx
	roll	$5,		%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%ebp,		%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%edx,		%edi
	/* 20_39 32 */
	movl	(%esp),		%edx
	movl	8(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	32(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	52(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	%esi,		%ebp
.byte 209
.byte 194		/* roll $1 %edx */
	xorl	%eax,		%ebp
	movl	%edx,		(%esp)
	xorl	%ebx,		%ebp
	leal	1859775393(%edx,%ecx,1),%edx
	movl	%edi,		%ecx
	roll	$5,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	addl	%ebp,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	addl	%ecx,		%edx
	/* 20_39 33 */
	movl	4(%esp),	%ecx
	movl	12(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	36(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	56(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	%edi,		%ebp
.byte 209
.byte 193		/* roll $1 %ecx */
	xorl	%esi,		%ebp
	movl	%ecx,		4(%esp)
	xorl	%eax,		%ebp
	leal	1859775393(%ecx,%ebx,1),%ecx
	movl	%edx,		%ebx
	roll	$5,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebp,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebx,		%ecx
	/* 20_39 34 */
	movl	8(%esp),	%ebx
	movl	16(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	40(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	60(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	%edx,		%ebp
.byte 209
.byte 195		/* roll $1 %ebx */
	xorl	%edi,		%ebp
	movl	%ebx,		8(%esp)
	xorl	%esi,		%ebp
	leal	1859775393(%ebx,%eax,1),%ebx
	movl	%ecx,		%eax
	roll	$5,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	addl	%ebp,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	addl	%eax,		%ebx
	/* 20_39 35 */
	movl	12(%esp),	%eax
	movl	20(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	44(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	(%esp),		%ebp
	xorl	%ebp,		%eax
	movl	%ecx,		%ebp
.byte 209
.byte 192		/* roll $1 %eax */
	xorl	%edx,		%ebp
	movl	%eax,		12(%esp)
	xorl	%edi,		%ebp
	leal	1859775393(%eax,%esi,1),%eax
	movl	%ebx,		%esi
	roll	$5,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%ebp,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%esi,		%eax
	/* 20_39 36 */
	movl	16(%esp),	%esi
	movl	24(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	48(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	4(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	%ebx,		%ebp
.byte 209
.byte 198		/* roll $1 %esi */
	xorl	%ecx,		%ebp
	movl	%esi,		16(%esp)
	xorl	%edx,		%ebp
	leal	1859775393(%esi,%edi,1),%esi
	movl	%eax,		%edi
	roll	$5,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	addl	%ebp,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	addl	%edi,		%esi
	/* 20_39 37 */
	movl	20(%esp),	%edi
	movl	28(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	52(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	8(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	%eax,		%ebp
.byte 209
.byte 199		/* roll $1 %edi */
	xorl	%ebx,		%ebp
	movl	%edi,		20(%esp)
	xorl	%ecx,		%ebp
	leal	1859775393(%edi,%edx,1),%edi
	movl	%esi,		%edx
	roll	$5,		%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%ebp,		%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%edx,		%edi
	/* 20_39 38 */
	movl	24(%esp),	%edx
	movl	32(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	56(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	12(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	%esi,		%ebp
.byte 209
.byte 194		/* roll $1 %edx */
	xorl	%eax,		%ebp
	movl	%edx,		24(%esp)
	xorl	%ebx,		%ebp
	leal	1859775393(%edx,%ecx,1),%edx
	movl	%edi,		%ecx
	roll	$5,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	addl	%ebp,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	addl	%ecx,		%edx
	/* 20_39 39 */
	movl	28(%esp),	%ecx
	movl	36(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	60(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	16(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	%edi,		%ebp
.byte 209
.byte 193		/* roll $1 %ecx */
	xorl	%esi,		%ebp
	movl	%ecx,		28(%esp)
	xorl	%eax,		%ebp
	leal	1859775393(%ecx,%ebx,1),%ecx
	movl	%edx,		%ebx
	roll	$5,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebp,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebx,		%ecx
	/* 40_59 40 */
	movl	32(%esp),	%ebx
	movl	40(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	(%esp),		%ebp
	xorl	%ebp,		%ebx
	movl	20(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	%edx,		%ebp
.byte 209
.byte 195		/* roll $1 %ebx */
	orl	%edi,		%ebp
	movl	%ebx,		32(%esp)
	andl	%esi,		%ebp
	leal	2400959708(%ebx,%eax,1),%ebx
	movl	%edx,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	andl	%edi,		%eax
	orl	%eax,		%ebp
	movl	%ecx,		%eax
	roll	$5,		%eax
	addl	%eax,		%ebp
	movl	36(%esp),	%eax
	addl	%ebp,		%ebx
	movl	44(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	4(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	24(%esp),	%ebp
.byte 209
.byte 202		/* rorl $1 %edx */
	xorl	%ebp,		%eax
.byte 209
.byte 192		/* roll $1 %eax */
	movl	%ecx,		%ebp
	movl	%eax,		36(%esp)
	orl	%edx,		%ebp
	leal	2400959708(%eax,%esi,1),%eax
	movl	%ecx,		%esi
	andl	%edi,		%ebp
	andl	%edx,		%esi
	orl	%esi,		%ebp
	movl	%ebx,		%esi
	roll	$5,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%esi,		%ebp
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%ebp,		%eax
	/* 40_59 41 */
	/* 40_59 42 */
	movl	40(%esp),	%esi
	movl	48(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	8(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	28(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	%ebx,		%ebp
.byte 209
.byte 198		/* roll $1 %esi */
	orl	%ecx,		%ebp
	movl	%esi,		40(%esp)
	andl	%edx,		%ebp
	leal	2400959708(%esi,%edi,1),%esi
	movl	%ebx,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	andl	%ecx,		%edi
	orl	%edi,		%ebp
	movl	%eax,		%edi
	roll	$5,		%edi
	addl	%edi,		%ebp
	movl	44(%esp),	%edi
	addl	%ebp,		%esi
	movl	52(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	12(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	32(%esp),	%ebp
.byte 209
.byte 203		/* rorl $1 %ebx */
	xorl	%ebp,		%edi
.byte 209
.byte 199		/* roll $1 %edi */
	movl	%eax,		%ebp
	movl	%edi,		44(%esp)
	orl	%ebx,		%ebp
	leal	2400959708(%edi,%edx,1),%edi
	movl	%eax,		%edx
	andl	%ecx,		%ebp
	andl	%ebx,		%edx
	orl	%edx,		%ebp
	movl	%esi,		%edx
	roll	$5,		%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%edx,		%ebp
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%ebp,		%edi
	/* 40_59 43 */
	/* 40_59 44 */
	movl	48(%esp),	%edx
	movl	56(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	16(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	36(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	%esi,		%ebp
.byte 209
.byte 194		/* roll $1 %edx */
	orl	%eax,		%ebp
	movl	%edx,		48(%esp)
	andl	%ebx,		%ebp
	leal	2400959708(%edx,%ecx,1),%edx
	movl	%esi,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	andl	%eax,		%ecx
	orl	%ecx,		%ebp
	movl	%edi,		%ecx
	roll	$5,		%ecx
	addl	%ecx,		%ebp
	movl	52(%esp),	%ecx
	addl	%ebp,		%edx
	movl	60(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	20(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	40(%esp),	%ebp
.byte 209
.byte 206		/* rorl $1 %esi */
	xorl	%ebp,		%ecx
.byte 209
.byte 193		/* roll $1 %ecx */
	movl	%edi,		%ebp
	movl	%ecx,		52(%esp)
	orl	%esi,		%ebp
	leal	2400959708(%ecx,%ebx,1),%ecx
	movl	%edi,		%ebx
	andl	%eax,		%ebp
	andl	%esi,		%ebx
	orl	%ebx,		%ebp
	movl	%edx,		%ebx
	roll	$5,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebx,		%ebp
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebp,		%ecx
	/* 40_59 45 */
	/* 40_59 46 */
	movl	56(%esp),	%ebx
	movl	(%esp),		%ebp
	xorl	%ebp,		%ebx
	movl	24(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	44(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	%edx,		%ebp
.byte 209
.byte 195		/* roll $1 %ebx */
	orl	%edi,		%ebp
	movl	%ebx,		56(%esp)
	andl	%esi,		%ebp
	leal	2400959708(%ebx,%eax,1),%ebx
	movl	%edx,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	andl	%edi,		%eax
	orl	%eax,		%ebp
	movl	%ecx,		%eax
	roll	$5,		%eax
	addl	%eax,		%ebp
	movl	60(%esp),	%eax
	addl	%ebp,		%ebx
	movl	4(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	28(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	48(%esp),	%ebp
.byte 209
.byte 202		/* rorl $1 %edx */
	xorl	%ebp,		%eax
.byte 209
.byte 192		/* roll $1 %eax */
	movl	%ecx,		%ebp
	movl	%eax,		60(%esp)
	orl	%edx,		%ebp
	leal	2400959708(%eax,%esi,1),%eax
	movl	%ecx,		%esi
	andl	%edi,		%ebp
	andl	%edx,		%esi
	orl	%esi,		%ebp
	movl	%ebx,		%esi
	roll	$5,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%esi,		%ebp
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%ebp,		%eax
	/* 40_59 47 */
	/* 40_59 48 */
	movl	(%esp),		%esi
	movl	8(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	32(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	52(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	%ebx,		%ebp
.byte 209
.byte 198		/* roll $1 %esi */
	orl	%ecx,		%ebp
	movl	%esi,		(%esp)
	andl	%edx,		%ebp
	leal	2400959708(%esi,%edi,1),%esi
	movl	%ebx,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	andl	%ecx,		%edi
	orl	%edi,		%ebp
	movl	%eax,		%edi
	roll	$5,		%edi
	addl	%edi,		%ebp
	movl	4(%esp),	%edi
	addl	%ebp,		%esi
	movl	12(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	36(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	56(%esp),	%ebp
.byte 209
.byte 203		/* rorl $1 %ebx */
	xorl	%ebp,		%edi
.byte 209
.byte 199		/* roll $1 %edi */
	movl	%eax,		%ebp
	movl	%edi,		4(%esp)
	orl	%ebx,		%ebp
	leal	2400959708(%edi,%edx,1),%edi
	movl	%eax,		%edx
	andl	%ecx,		%ebp
	andl	%ebx,		%edx
	orl	%edx,		%ebp
	movl	%esi,		%edx
	roll	$5,		%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%edx,		%ebp
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%ebp,		%edi
	/* 40_59 49 */
	/* 40_59 50 */
	movl	8(%esp),	%edx
	movl	16(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	40(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	60(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	%esi,		%ebp
.byte 209
.byte 194		/* roll $1 %edx */
	orl	%eax,		%ebp
	movl	%edx,		8(%esp)
	andl	%ebx,		%ebp
	leal	2400959708(%edx,%ecx,1),%edx
	movl	%esi,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	andl	%eax,		%ecx
	orl	%ecx,		%ebp
	movl	%edi,		%ecx
	roll	$5,		%ecx
	addl	%ecx,		%ebp
	movl	12(%esp),	%ecx
	addl	%ebp,		%edx
	movl	20(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	44(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	(%esp),		%ebp
.byte 209
.byte 206		/* rorl $1 %esi */
	xorl	%ebp,		%ecx
.byte 209
.byte 193		/* roll $1 %ecx */
	movl	%edi,		%ebp
	movl	%ecx,		12(%esp)
	orl	%esi,		%ebp
	leal	2400959708(%ecx,%ebx,1),%ecx
	movl	%edi,		%ebx
	andl	%eax,		%ebp
	andl	%esi,		%ebx
	orl	%ebx,		%ebp
	movl	%edx,		%ebx
	roll	$5,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebx,		%ebp
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebp,		%ecx
	/* 40_59 51 */
	/* 40_59 52 */
	movl	16(%esp),	%ebx
	movl	24(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	48(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	4(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	%edx,		%ebp
.byte 209
.byte 195		/* roll $1 %ebx */
	orl	%edi,		%ebp
	movl	%ebx,		16(%esp)
	andl	%esi,		%ebp
	leal	2400959708(%ebx,%eax,1),%ebx
	movl	%edx,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	andl	%edi,		%eax
	orl	%eax,		%ebp
	movl	%ecx,		%eax
	roll	$5,		%eax
	addl	%eax,		%ebp
	movl	20(%esp),	%eax
	addl	%ebp,		%ebx
	movl	28(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	52(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	8(%esp),	%ebp
.byte 209
.byte 202		/* rorl $1 %edx */
	xorl	%ebp,		%eax
.byte 209
.byte 192		/* roll $1 %eax */
	movl	%ecx,		%ebp
	movl	%eax,		20(%esp)
	orl	%edx,		%ebp
	leal	2400959708(%eax,%esi,1),%eax
	movl	%ecx,		%esi
	andl	%edi,		%ebp
	andl	%edx,		%esi
	orl	%esi,		%ebp
	movl	%ebx,		%esi
	roll	$5,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%esi,		%ebp
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%ebp,		%eax
	/* 40_59 53 */
	/* 40_59 54 */
	movl	24(%esp),	%esi
	movl	32(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	56(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	12(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	%ebx,		%ebp
.byte 209
.byte 198		/* roll $1 %esi */
	orl	%ecx,		%ebp
	movl	%esi,		24(%esp)
	andl	%edx,		%ebp
	leal	2400959708(%esi,%edi,1),%esi
	movl	%ebx,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	andl	%ecx,		%edi
	orl	%edi,		%ebp
	movl	%eax,		%edi
	roll	$5,		%edi
	addl	%edi,		%ebp
	movl	28(%esp),	%edi
	addl	%ebp,		%esi
	movl	36(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	60(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	16(%esp),	%ebp
.byte 209
.byte 203		/* rorl $1 %ebx */
	xorl	%ebp,		%edi
.byte 209
.byte 199		/* roll $1 %edi */
	movl	%eax,		%ebp
	movl	%edi,		28(%esp)
	orl	%ebx,		%ebp
	leal	2400959708(%edi,%edx,1),%edi
	movl	%eax,		%edx
	andl	%ecx,		%ebp
	andl	%ebx,		%edx
	orl	%edx,		%ebp
	movl	%esi,		%edx
	roll	$5,		%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%edx,		%ebp
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%ebp,		%edi
	/* 40_59 55 */
	/* 40_59 56 */
	movl	32(%esp),	%edx
	movl	40(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	(%esp),		%ebp
	xorl	%ebp,		%edx
	movl	20(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	%esi,		%ebp
.byte 209
.byte 194		/* roll $1 %edx */
	orl	%eax,		%ebp
	movl	%edx,		32(%esp)
	andl	%ebx,		%ebp
	leal	2400959708(%edx,%ecx,1),%edx
	movl	%esi,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	andl	%eax,		%ecx
	orl	%ecx,		%ebp
	movl	%edi,		%ecx
	roll	$5,		%ecx
	addl	%ecx,		%ebp
	movl	36(%esp),	%ecx
	addl	%ebp,		%edx
	movl	44(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	4(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	24(%esp),	%ebp
.byte 209
.byte 206		/* rorl $1 %esi */
	xorl	%ebp,		%ecx
.byte 209
.byte 193		/* roll $1 %ecx */
	movl	%edi,		%ebp
	movl	%ecx,		36(%esp)
	orl	%esi,		%ebp
	leal	2400959708(%ecx,%ebx,1),%ecx
	movl	%edi,		%ebx
	andl	%eax,		%ebp
	andl	%esi,		%ebx
	orl	%ebx,		%ebp
	movl	%edx,		%ebx
	roll	$5,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebx,		%ebp
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebp,		%ecx
	/* 40_59 57 */
	/* 40_59 58 */
	movl	40(%esp),	%ebx
	movl	48(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	8(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	28(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	%edx,		%ebp
.byte 209
.byte 195		/* roll $1 %ebx */
	orl	%edi,		%ebp
	movl	%ebx,		40(%esp)
	andl	%esi,		%ebp
	leal	2400959708(%ebx,%eax,1),%ebx
	movl	%edx,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	andl	%edi,		%eax
	orl	%eax,		%ebp
	movl	%ecx,		%eax
	roll	$5,		%eax
	addl	%eax,		%ebp
	movl	44(%esp),	%eax
	addl	%ebp,		%ebx
	movl	52(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	12(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	32(%esp),	%ebp
.byte 209
.byte 202		/* rorl $1 %edx */
	xorl	%ebp,		%eax
.byte 209
.byte 192		/* roll $1 %eax */
	movl	%ecx,		%ebp
	movl	%eax,		44(%esp)
	orl	%edx,		%ebp
	leal	2400959708(%eax,%esi,1),%eax
	movl	%ecx,		%esi
	andl	%edi,		%ebp
	andl	%edx,		%esi
	orl	%esi,		%ebp
	movl	%ebx,		%esi
	roll	$5,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%esi,		%ebp
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%ebp,		%eax
	/* 40_59 59 */
	/* 20_39 60 */
	movl	48(%esp),	%esi
	movl	56(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	16(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	36(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	%ebx,		%ebp
.byte 209
.byte 198		/* roll $1 %esi */
	xorl	%ecx,		%ebp
	movl	%esi,		48(%esp)
	xorl	%edx,		%ebp
	leal	3395469782(%esi,%edi,1),%esi
	movl	%eax,		%edi
	roll	$5,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	addl	%ebp,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	addl	%edi,		%esi
	/* 20_39 61 */
	movl	52(%esp),	%edi
	movl	60(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	20(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	40(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	%eax,		%ebp
.byte 209
.byte 199		/* roll $1 %edi */
	xorl	%ebx,		%ebp
	movl	%edi,		52(%esp)
	xorl	%ecx,		%ebp
	leal	3395469782(%edi,%edx,1),%edi
	movl	%esi,		%edx
	roll	$5,		%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%ebp,		%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%edx,		%edi
	/* 20_39 62 */
	movl	56(%esp),	%edx
	movl	(%esp),		%ebp
	xorl	%ebp,		%edx
	movl	24(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	44(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	%esi,		%ebp
.byte 209
.byte 194		/* roll $1 %edx */
	xorl	%eax,		%ebp
	movl	%edx,		56(%esp)
	xorl	%ebx,		%ebp
	leal	3395469782(%edx,%ecx,1),%edx
	movl	%edi,		%ecx
	roll	$5,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	addl	%ebp,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	addl	%ecx,		%edx
	/* 20_39 63 */
	movl	60(%esp),	%ecx
	movl	4(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	28(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	48(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	%edi,		%ebp
.byte 209
.byte 193		/* roll $1 %ecx */
	xorl	%esi,		%ebp
	movl	%ecx,		60(%esp)
	xorl	%eax,		%ebp
	leal	3395469782(%ecx,%ebx,1),%ecx
	movl	%edx,		%ebx
	roll	$5,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebp,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebx,		%ecx
	/* 20_39 64 */
	movl	(%esp),		%ebx
	movl	8(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	32(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	52(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	%edx,		%ebp
.byte 209
.byte 195		/* roll $1 %ebx */
	xorl	%edi,		%ebp
	movl	%ebx,		(%esp)
	xorl	%esi,		%ebp
	leal	3395469782(%ebx,%eax,1),%ebx
	movl	%ecx,		%eax
	roll	$5,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	addl	%ebp,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	addl	%eax,		%ebx
	/* 20_39 65 */
	movl	4(%esp),	%eax
	movl	12(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	36(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	56(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	%ecx,		%ebp
.byte 209
.byte 192		/* roll $1 %eax */
	xorl	%edx,		%ebp
	movl	%eax,		4(%esp)
	xorl	%edi,		%ebp
	leal	3395469782(%eax,%esi,1),%eax
	movl	%ebx,		%esi
	roll	$5,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%ebp,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%esi,		%eax
	/* 20_39 66 */
	movl	8(%esp),	%esi
	movl	16(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	40(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	60(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	%ebx,		%ebp
.byte 209
.byte 198		/* roll $1 %esi */
	xorl	%ecx,		%ebp
	movl	%esi,		8(%esp)
	xorl	%edx,		%ebp
	leal	3395469782(%esi,%edi,1),%esi
	movl	%eax,		%edi
	roll	$5,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	addl	%ebp,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	addl	%edi,		%esi
	/* 20_39 67 */
	movl	12(%esp),	%edi
	movl	20(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	44(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	(%esp),		%ebp
	xorl	%ebp,		%edi
	movl	%eax,		%ebp
.byte 209
.byte 199		/* roll $1 %edi */
	xorl	%ebx,		%ebp
	movl	%edi,		12(%esp)
	xorl	%ecx,		%ebp
	leal	3395469782(%edi,%edx,1),%edi
	movl	%esi,		%edx
	roll	$5,		%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%ebp,		%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%edx,		%edi
	/* 20_39 68 */
	movl	16(%esp),	%edx
	movl	24(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	48(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	4(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	%esi,		%ebp
.byte 209
.byte 194		/* roll $1 %edx */
	xorl	%eax,		%ebp
	movl	%edx,		16(%esp)
	xorl	%ebx,		%ebp
	leal	3395469782(%edx,%ecx,1),%edx
	movl	%edi,		%ecx
	roll	$5,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	addl	%ebp,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	addl	%ecx,		%edx
	/* 20_39 69 */
	movl	20(%esp),	%ecx
	movl	28(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	52(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	8(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	%edi,		%ebp
.byte 209
.byte 193		/* roll $1 %ecx */
	xorl	%esi,		%ebp
	movl	%ecx,		20(%esp)
	xorl	%eax,		%ebp
	leal	3395469782(%ecx,%ebx,1),%ecx
	movl	%edx,		%ebx
	roll	$5,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebp,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebx,		%ecx
	/* 20_39 70 */
	movl	24(%esp),	%ebx
	movl	32(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	56(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	12(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	%edx,		%ebp
.byte 209
.byte 195		/* roll $1 %ebx */
	xorl	%edi,		%ebp
	movl	%ebx,		24(%esp)
	xorl	%esi,		%ebp
	leal	3395469782(%ebx,%eax,1),%ebx
	movl	%ecx,		%eax
	roll	$5,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	addl	%ebp,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	addl	%eax,		%ebx
	/* 20_39 71 */
	movl	28(%esp),	%eax
	movl	36(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	60(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	16(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	%ecx,		%ebp
.byte 209
.byte 192		/* roll $1 %eax */
	xorl	%edx,		%ebp
	movl	%eax,		28(%esp)
	xorl	%edi,		%ebp
	leal	3395469782(%eax,%esi,1),%eax
	movl	%ebx,		%esi
	roll	$5,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%ebp,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%esi,		%eax
	/* 20_39 72 */
	movl	32(%esp),	%esi
	movl	40(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	(%esp),		%ebp
	xorl	%ebp,		%esi
	movl	20(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	%ebx,		%ebp
.byte 209
.byte 198		/* roll $1 %esi */
	xorl	%ecx,		%ebp
	movl	%esi,		32(%esp)
	xorl	%edx,		%ebp
	leal	3395469782(%esi,%edi,1),%esi
	movl	%eax,		%edi
	roll	$5,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	addl	%ebp,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	addl	%edi,		%esi
	/* 20_39 73 */
	movl	36(%esp),	%edi
	movl	44(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	4(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	24(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	%eax,		%ebp
.byte 209
.byte 199		/* roll $1 %edi */
	xorl	%ebx,		%ebp
	movl	%edi,		36(%esp)
	xorl	%ecx,		%ebp
	leal	3395469782(%edi,%edx,1),%edi
	movl	%esi,		%edx
	roll	$5,		%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%ebp,		%edx
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%edx,		%edi
	/* 20_39 74 */
	movl	40(%esp),	%edx
	movl	48(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	8(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	28(%esp),	%ebp
	xorl	%ebp,		%edx
	movl	%esi,		%ebp
.byte 209
.byte 194		/* roll $1 %edx */
	xorl	%eax,		%ebp
	movl	%edx,		40(%esp)
	xorl	%ebx,		%ebp
	leal	3395469782(%edx,%ecx,1),%edx
	movl	%edi,		%ecx
	roll	$5,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	addl	%ebp,		%ecx
.byte 209
.byte 206		/* rorl $1 %esi */
	addl	%ecx,		%edx
	/* 20_39 75 */
	movl	44(%esp),	%ecx
	movl	52(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	12(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	32(%esp),	%ebp
	xorl	%ebp,		%ecx
	movl	%edi,		%ebp
.byte 209
.byte 193		/* roll $1 %ecx */
	xorl	%esi,		%ebp
	movl	%ecx,		44(%esp)
	xorl	%eax,		%ebp
	leal	3395469782(%ecx,%ebx,1),%ecx
	movl	%edx,		%ebx
	roll	$5,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebp,		%ebx
.byte 209
.byte 207		/* rorl $1 %edi */
	addl	%ebx,		%ecx
	/* 20_39 76 */
	movl	48(%esp),	%ebx
	movl	56(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	16(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	36(%esp),	%ebp
	xorl	%ebp,		%ebx
	movl	%edx,		%ebp
.byte 209
.byte 195		/* roll $1 %ebx */
	xorl	%edi,		%ebp
	movl	%ebx,		48(%esp)
	xorl	%esi,		%ebp
	leal	3395469782(%ebx,%eax,1),%ebx
	movl	%ecx,		%eax
	roll	$5,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	addl	%ebp,		%eax
.byte 209
.byte 202		/* rorl $1 %edx */
	addl	%eax,		%ebx
	/* 20_39 77 */
	movl	52(%esp),	%eax
	movl	60(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	20(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	40(%esp),	%ebp
	xorl	%ebp,		%eax
	movl	%ecx,		%ebp
.byte 209
.byte 192		/* roll $1 %eax */
	xorl	%edx,		%ebp
	movl	%eax,		52(%esp)
	xorl	%edi,		%ebp
	leal	3395469782(%eax,%esi,1),%eax
	movl	%ebx,		%esi
	roll	$5,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%ebp,		%esi
.byte 209
.byte 201		/* rorl $1 %ecx */
	addl	%esi,		%eax
	/* 20_39 78 */
	movl	56(%esp),	%esi
	movl	(%esp),		%ebp
	xorl	%ebp,		%esi
	movl	24(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	44(%esp),	%ebp
	xorl	%ebp,		%esi
	movl	%ebx,		%ebp
.byte 209
.byte 198		/* roll $1 %esi */
	xorl	%ecx,		%ebp
	movl	%esi,		56(%esp)
	xorl	%edx,		%ebp
	leal	3395469782(%esi,%edi,1),%esi
	movl	%eax,		%edi
	roll	$5,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	addl	%ebp,		%edi
.byte 209
.byte 203		/* rorl $1 %ebx */
	addl	%edi,		%esi
	/* 20_39 79 */
	movl	60(%esp),	%edi
	movl	4(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	28(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	48(%esp),	%ebp
	xorl	%ebp,		%edi
	movl	%eax,		%ebp
.byte 209
.byte 199		/* roll $1 %edi */
	xorl	%ebx,		%ebp
	movl	%edi,		60(%esp)
	xorl	%ecx,		%ebp
	leal	3395469782(%edi,%edx,1),%edi
	movl	%esi,		%edx
	roll	$5,		%edx
	addl	%ebp,		%edx
	movl	92(%esp),	%ebp
.byte 209
.byte 200		/* rorl $1 %eax */
	addl	%edx,		%edi
.byte 209
.byte 200		/* rorl $1 %eax */
	/* End processing */

	movl	12(%ebp),	%edx
	addl	%ebx,		%edx
	movl	4(%ebp),	%ebx
	addl	%esi,		%ebx
	movl	%eax,		%esi
	movl	(%ebp),		%eax
	movl	%edx,		12(%ebp)
	addl	%edi,		%eax
	movl	16(%ebp),	%edi
	addl	%ecx,		%edi
	movl	8(%ebp),	%ecx
	addl	%esi,		%ecx
	movl	%eax,		(%ebp)
	movl	%ecx,		8(%ebp)
	movl	64(%esp),	%esi
	movl	%edi,		16(%ebp)
	addl	$64,		%esi
	movl	68(%esp),	%eax
	movl	%ebx,		4(%ebp)
	cmpl	%esi,		%eax
	movl	(%esi),		%eax
	jge	.L000start
	addl	$72,		%esp
	popl	%edi
	popl	%ebx
	popl	%ebp
	popl	%esi
	ret
.sha1_block_x86_end:
	SIZE(sha1_block_x86,.sha1_block_x86_end-sha1_block_x86)
.ident	"desasm.pl"

VERSION		EQU	0
REVISION	EQU	1
DATE	MACRO
		dc.b	'08.06.06'
	ENDM
VERS	MACRO
		dc.b	'cyassl.library 0.1'
	ENDM
VSTRING	MACRO
		dc.b	'cyassl.library 0.1 (07.04.15) © 2015 by Filip "widelec" Maryjanski, written by wolfSSL',13,10,0
	ENDM
VERSTAG	MACRO
		dc.b	0,'$VER: cyassl.library 0.1 (07.04.15) © 2015 by Filip "widelec" Maryjanski, written by wolfSSL',0
	ENDM

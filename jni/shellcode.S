.code 16

//Seeking out to the location of the encryption key
SUB R3, R3, #0x10

//Coping out both keys to the shared buffer
MOV R2, #0x0
loop:
LDR R0, [R3, R2]
STR R0, [R1, R2]
ADD R2, R2, #0x4
MOV R0, #0x30
SUB R0, R2, R0
BLT loop

//Returning success
MOV R0, #0
BX LR


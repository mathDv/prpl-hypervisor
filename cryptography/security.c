/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
//#include "./include/uECC.h"
#include <libc.h>
#include <uECC.h>
#include "./include/types.h"
#include <sha256.h>
#include <security.h>
#include <hal.h>
#include <libc.h>
#include <vm.h>
#include <config.h>
#include <vm.h>
#include <globals.h>
#include <hypercall_defines.h>
#include <hypercall.h>

#define NUM_ECC_DIGITS 32
//#define DEBUG 
#define NUM_TESTS 200

static int diffieHelman(void);
static int ecdsa(void);

int isVmTrust(void) {

    unsigned char isVmTrust = 0;
#ifdef DEBUG
    uint32_t initialCountTotal = 0, finalCountTotal = 0;
    uint32_t initialCountHash = 0, finalCountHash = 0;
    uint32_t initialCountVerifySignature = 0;
    uint32_t initialCountVerifyPK = 0, finalCounterVerifyPK = 0;
    uint32_t TotalPK = 0, TotalHash = 0, Total = 0, TotalSignature = 0;
#endif

    unsigned char *lAddrVm = NULL;
    int countNumMachines = 0;


#ifdef DEBUG
    int countNumtests = 0;
    for (; countNumtests < NUM_TESTS; countNumtests++) {
#endif
        countNumMachines = 0;
        //loop to verify all vms
        for (; countNumMachines < NVMACHINES; countNumMachines++) {
#ifdef DEBUG
            initialCountTotal = getCounter();
#endif
            (lAddrVm) = (unsigned char*) VMCONF[countNumMachines].flash_base_add;

            //INFO("Configuring VM %d, of size %d FLASH size, address: %x.\n\n", countNumMachines, VMCONF[countNumMachines].flash_size, (char*) lAddrVm);

            int countSign = 0, countPubKey = 0;
            long sizeVm = VMCONF[countNumMachines].flash_size; //size VM+pubKey+signature 
            long sizeHash = sizeVm - 128; //only the size to calculate hash of vm
            uint8_t public[64];
            uint8_t sigReceived[64];

            //----------------------------------------------------------------------
            //read public key
            for (countPubKey = 0; countPubKey < 64; countPubKey++) {
                public[countPubKey] = lAddrVm[(sizeVm - 128) + countPubKey];
            }
            //debug public key
            //            printf("uint8_t PubKey[2*NUM_ECC_DIGITS] = {");
            //            vli_print(public, sizeof (public));
            //            printf("};\n");
            //            printf("\n\n");
#ifdef DEBUG
            initialCountVerifyPK = getCounter();
#endif
            //verify public key
            if (!uECC_valid_public_key(public, uECC_secp256k1())) {
                //                printf("\nuECC_valid_public_key() failed\n");
                return 1;
            } else {
                //                printf("\nValid Public Key\n");
            }
#ifdef DEBUG
            finalCounterVerifyPK = getCounter();
#endif
            //----------------------------------------------------------------------
            //read signature
            for (countSign = 0; countSign < 64; countSign++) {
                sigReceived[countSign] = lAddrVm[(sizeVm - 64) + countSign];
            }
            //debug signature
            //            printf("uint8_t Signature[2*NUM_ECC_DIGITS] = {");
            //            vli_print(sigReceived, sizeof (sigReceived));
            //            printf("};\n");
            //            printf("\n\n");
            //----------------------------------------------------------------------

#ifdef DEBUG
            initialCountHash = getCounter();
#endif
            //----------------------------------------------------------------------
            SHA256_CTX contextHash;
            BYTE buf[SHA256_BLOCK_SIZE];
            sha256_init(&contextHash);
            sha256_update(&contextHash, lAddrVm, sizeHash);
            sha256_final(&contextHash, buf);
#ifdef DEBUG
            finalCountHash = getCounter();
#endif
            //debug hash
            //            printf("uint8_t hash[NUM_ECC_DIGITS] = {");
            //            vli_print(buf, sizeof (buf));
            //            printf("};\n");
            //            printf("\n\n");
            //----------------------------------------------------------------------

            /*tests to detect fail*/
            //public[10]=0xAA;
            //sigReceived[1]=0xAA;
            //buf[30]=0xAA;


#ifdef DEBUG
            initialCountVerifySignature = getCounter();
#endif
            //----------------------------------------------------------------------
            //verify signature
            if (!uECC_verify(public, buf, sizeof (buf), sigReceived, uECC_secp256k1())) {
                //                printf("uECC_verify() failed\n");
                return 1;
            } else {
                //                printf("uECC_verify() OK\n");
                isVmTrust = 1;
            }
            //----------------------------------------------------------------------
#ifdef DEBUG
            finalCountTotal = getCounter();
#endif


#ifdef DEBUG
            TotalPK += (finalCounterVerifyPK - initialCountVerifyPK);
            TotalHash += (finalCountHash - initialCountHash);
            Total += (finalCountTotal - initialCountTotal);
            TotalSignature += (finalCountTotal - initialCountVerifySignature);
#endif
        }
#ifdef DEBUG
    }
#endif

#ifdef DEBUG
    //    printf("Count TOTAL:                  %d\n", Total / (NUM_TESTS * NVMACHINES));
    //    printf("Count TOTAL HASh:             %d\n", TotalHash / (NUM_TESTS * NVMACHINES));
    //    printf("Count TOTAL Verify PK:        %d\n", TotalPK / (NUM_TESTS * NVMACHINES));
    //    printf("Count TOTAL Verify Signature: %d\n", TotalSignature / (NUM_TESTS * NVMACHINES));
    finalCountTotal = 0;
    initialCountTotal = 0;
    finalCountHash = 0;
    initialCountHash = 0;
#endif
    return isVmTrust;
}

int identifyHypercalls(void) {

    //    printf("\n\rVerifies Hypercalls");
#ifdef DEBUG
    uint32_t initialCountTotal = 0, finalCountTotal = 0;
    initialCountTotal = getCounter();
#endif


    unsigned char hypercallsAuthorized[NVMACHINES][30] = {
        {0}
    };

    //initiates hypercall matrix
    int line = 0, column = 0;
    for (; line < NVMACHINES; line++) {
        for (; column < HCALL_TABLE_SIZE; column++) {
            hypercallsAuthorized[line][column] = 0;
        }
    }
    unsigned char *lAddrVm = NULL;
    long lCount = 0;
    long sizeVm = VMCONF[0].flash_size;
    //point to vm add
    (lAddrVm) = (unsigned char*) VMCONF[0].flash_base_add;


    uint32_t guestID = getGuestID();
    //    printf("\n\rGuestID: %d", guestID);

    //    int count = 0;

    for (; lCount < (sizeVm - 4); lCount++) {

        if (lAddrVm[lCount] == 0x28) {//identify firt hyp instruction code
            switch (lAddrVm[lCount + 1]) {
                case 0x00:
                    if ((lAddrVm[lCount + 2] == 0x00) && (lAddrVm[lCount + 3] == 0x42)) {
                        hypercallsAuthorized[guestID][HCALL_GET_VM_ID] = 1;
                        //                        printf("\n\rFind Hyper 0\n");
                    }
                    break;
                case 0x08:
                    if ((lAddrVm[lCount + 2] == 0x00) && (lAddrVm[lCount + 3] == 0x42)) {
                        //                        printf("\n\rFind Hyper 0\n");
                        hypercallsAuthorized[guestID][HCALL_IPC_RECV_MSG] = 1;
                    }
                    break;
                case 0x10:
                    if ((lAddrVm[lCount + 2] == 0x00) && (lAddrVm[lCount + 3] == 0x42)) {
                        //                        printf("\n\rFind Hyper 0\n");
                        hypercallsAuthorized[guestID][HCALL_IPC_SEND_MSG] = 1;
                    }
                    break;
                    //                case 0x10:
                    //                    if ((lAddrVm[lCount + 2] == 0x00) && (lAddrVm[lCount + 3] == 0x42)) {
                    //                        //printf("\n\rFind Hyper 0\n");
                    //                        hypercallsAuthorized[getGuestID()][HCALL_GUEST_UP] = 1;
                    //                    } else {
                    //                        //                        lCount+=2;
                    //                    }
                    //                    break;
                case 0x20:
                    if ((lAddrVm[lCount + 2] == 0x00) && (lAddrVm[lCount + 3] == 0x42)) {
                        //lCount+=4;
                        //                        printf("\n\rFind Hyper 0x4\n");
                        hypercallsAuthorized[guestID][HCALL_ETHERNET_WATCHDOG] = 1;
                    }
                    break;
                case 0x28:
                    if ((lAddrVm[lCount + 2] == 0x00) && (lAddrVm[lCount + 3] == 0x42)) {
                        //                        printf("\n\rFind Hyper 0x5\n");
                        hypercallsAuthorized[guestID][HCALL_ETHERNET_SEND] = 1;
                    }
                    break;
                case 0x30:
                    if ((lAddrVm[lCount + 2] == 0x00) && (lAddrVm[lCount + 3] == 0x42)) {
                        //                        printf("\n\rFind Hyper 0x6\n");
                        hypercallsAuthorized[guestID][HCALL_ETHERNET_RECV] = 1;
                    }
                    break;
                case 0x38:
                    if ((lAddrVm[lCount + 2] == 0x00) && (lAddrVm[lCount + 3] == 0x42)) {
                        //                        printf("\n\rFind Hyper 0x7\n");
                        hypercallsAuthorized[guestID][HCALL_ETHERNET_GET_MAC] = 1;
                    }
                    break;
                case 0x40:
                    if ((lAddrVm[lCount + 2] == 0x00) && (lAddrVm[lCount + 3] == 0x42)) {
                        //                        printf("\n\rFind Hyper 0x8\n");
                        hypercallsAuthorized[guestID][HCALL_USB_POLLING] = 1;
                    }
                    break;
                    //                case 0x40:
                    //                    if ((lAddrVm[lCount + 2] == 0x00) && (lAddrVm[lCount + 3] == 0x42)) {
                    //                        //printf("\n\rFind Hyper 0x8\n");
                    //                        hypercallsAuthorized[getGuestID()][HCALL_USB_GET_DESCRIPTOR] = 1;
                    //                    } else {
                    //                        //                        lCount+=2;
                    //                    }
                    //                    break;
                case 0x50:
                    if ((lAddrVm[lCount + 2] == 0x00) && (lAddrVm[lCount + 3] == 0x42)) {
                        //                        printf("\n\rFind Hyper 0xA\n");
                        hypercallsAuthorized[guestID][HCALL_USB_SEND_DATA] = 1;
                    }
                    break;
                case 0x58:
                    if ((lAddrVm[lCount + 2] == 0x00) && (lAddrVm[lCount + 3] == 0x42)) {
                        //                        printf("\n\rFind Hyper 0xB\n");
                        hypercallsAuthorized[guestID][HCALL_WRITE_ADDRESS] = 1;
                    }
                    break;
                case 0x60:
                    if ((lAddrVm[lCount + 2] == 0x00) && (lAddrVm[lCount + 3] == 0x42)) {
                        //                        printf("\n\rFind Hyper 0xC\n");
                        hypercallsAuthorized[guestID][HCALL_READ_ADDRESS] = 1;
                    }
                    break;
                    //                case 0x60:
                    //                    if ((lAddrVm[lCount + 2] == 0x00) && (lAddrVm[lCount + 3] == 0x42)) {
                    //                        //printf("\n\rFind Hyper 0xC\n");
                    //                        hypercallsAuthorized[getGuestID()][HCALL_REENABLE_INTERRUPT] = 1;
                    //                    } else {
                    //                        //                        lCount+=2;
                    //                    }
                    //                    break;
                    //                case 0x60:
                    //                    if ((lAddrVm[lCount + 2] == 0x00) && (lAddrVm[lCount + 3] == 0x42)) {
                    //                        //printf("\n\rFind Hyper 0xC\n");
                    //                        hypercallsAuthorized[getGuestID()][HCALL_FLASH_READ] = 1;
                    //                    } else {
                    //                        //                        lCount+=2;
                    //                    }
                    //                    break;
                    //                case 0x60:
                    //                    if ((lAddrVm[lCount + 2] == 0x00) && (lAddrVm[lCount + 3] == 0x42)) {
                    //                        //printf("\n\rFind Hyper 0xC\n");
                    //                        hypercallsAuthorized[getGuestID()][HCALL_FLASH_WRITE] = 1;
                    //                    } else {
                    //                        //                        lCount+=2;
                    //                    }
                    //                    break;
                default:
                    //                    lCount+=4;
                    break;
            }
        }
        lCount++;
    }

#ifdef DEBUG
    finalCountTotal = getCounter();
    printf("\n\rTime TOTAL: %d", (finalCountTotal - initialCountTotal));

    printf("\n\rshow hypercalls table\n");
    int a = 0;
    for (; a < 15; a++) {
        printf("%x ", a);
    }
    printf("\n\r");

    int i = 0, j = 0;
    for (; i < NVMACHINES; i++) {
        for (; j < HCALL_TABLE_SIZE; j++) {
            printf("%d ", hypercallsAuthorized[i][j]);
        }
        printf("\n\r");
    }
#endif
    hypercallsAuthorized[guestID][HCALL_READ_ADDRESS] = 0;
    return 0;

}

/**
 * @brief generate 32bit TRNG
 * \param void
 * \return 32bit number generated
 * 
 */
void TRNG_Generator(void) {

    ecdsa();
    return;

    diffieHelman();
    return;
    /*
     * 1 - ler registrador de ID - ok
     * 2 - ler registrador de versao -ok
     * 2 - ler registrador de revisao - ok
     * 3 - iniciar RNG - ok
     * 4 - gerar 32 bits    - ok
     * 
     * 5 - substituir funcao para geracao chaves - ok
     * 5 - gerar par de chave - ok
     * 6 - medir tempo para geracao chaver - ok
     *   
     * 7 - assinar hash
     * 8 - medir tempo assinatura hash
     * 9 - teste diffie hellmam and others
     * 9 - "explorando segurança com mips pic32"
     */
    //#ifdef DEBUG

    //    pic32_rng(_private, 32);

    //    printf("\n");
    //    for(;i<4;i++){
    //        printf("%x", _private[i]);
    //    }
    //    printf("\n");

    //#ifdef DEBUG

    //#endif
    printf("\n\rTime make keys\n");
    uint32_t initialCountTotal = 0, finalCountTotal = 0;
    initialCountTotal = getCounter();
    uint8_t private[NUM_ECC_DIGITS];
    uint8_t public[NUM_ECC_DIGITS * 2];
    //    uint8_t sig[64] = {0}; //sigature - feito com a chave privada do emissor e entregue para que tem a chave publica verificar.
    //generate private/public key
    if (!uECC_make_key(public, private, uECC_secp256k1())) {
        printf("uECC_make_key() failed\n");
        //        return 1;
    }
    //valida public key
    if (!uECC_valid_public_key(public, uECC_secp256k1())) {
        //        printf("uECC_valid_public_key() failed\n");
        //        return 1;
    } else {
        //        printf("Public Key OK\n");
    }

    finalCountTotal = getCounter();
    printf("\n\rTime TOTAL: %d", (finalCountTotal - initialCountTotal));


    //show private key
    printf("\nuint8_t private[32] = {");
    vli_print(private, NUM_ECC_DIGITS);
    printf("};\n");
    printf("\n\n");
    //show public key
    printf("uint8_t public[64] = {");
    vli_print(public, NUM_ECC_DIGITS * 2);
    printf("};\n");
    //    printf("\n\n");
    /********************/
    //#endif
}

static int diffieHelman(void) {


    printf("\n\rTime DH\n");
    uint32_t initialCountTotal = 0, finalCountTotal = 0, initialCountmakeKey = 0,
            initialCountSharedKey = 0, finalCountmakeKeyTotal = 0, finalCountSharedKeyTotal = 0;



    uint32_t TotalDH = 0, TotalMakeKeys = 0, TotalShared = 0;

    int i = 1;
    uint8_t private1[32] = {0};
    uint8_t private2[32] = {0};
    uint8_t public1[64] = {0};
    uint8_t public2[64] = {0};
    uint8_t secret1[32] = {0};
    uint8_t secret2[32] = {0};

    initialCountTotal = getCounter();

    for (i = 0; i < NUM_TESTS; i++) {
        initialCountmakeKey = getCounter();
        if (!uECC_make_key(public1, private1, uECC_secp256k1()) ||
            !uECC_make_key(public2, private2, uECC_secp256k1())) {
            printf("uECC_make_key() failed\n");
            return 1;
        }
        finalCountmakeKeyTotal = getCounter();

        initialCountSharedKey = getCounter();
        if (!uECC_shared_secret(public2, private1, secret1, uECC_secp256k1())) {
            printf("shared_secret() failed (1)\n");
            return 1;
        }
        finalCountSharedKeyTotal = getCounter();

        //        if (!uECC_shared_secret(public1, private2, secret2, uECC_secp256k1())) {
        //            printf("shared_secret() failed (2)\n");
        //            return 1;
        //        }





        TotalMakeKeys += (finalCountmakeKeyTotal - initialCountmakeKey);
        TotalShared += (finalCountSharedKeyTotal - initialCountSharedKey);
    }
    finalCountTotal = getCounter();
    TotalDH = (finalCountTotal - initialCountTotal);

    printf("\n\rTime TOTAL: %d\n", TotalDH / NUM_TESTS);
    printf("\n\rTime TOTAL MAKEKEYS: %d\n", TotalMakeKeys / NUM_TESTS);
    printf("\n\rTime TOTAL SHARED KEYS: %d\n", TotalShared / NUM_TESTS);

    //    if (memcmp(secret1, secret2, sizeof (secret1)) != 0) {
    //    printf("Shared secrets are not identical!\n");
    printf("Private key 1 = ");
    vli_print(private1, 32);
    printf("\n");
    printf("Private key 2 = ");
    vli_print(private2, 32);
    printf("\n");
    printf("Public key 1 = ");
    vli_print(public1, 64);
    printf("\n");
    printf("Public key 2 = ");
    vli_print(public2, 64);
    printf("\n");
    printf("Shared secret 1 = ");
    vli_print(secret1, 32);
    printf("\n");
    printf("Shared secret 2 = ");
    vli_print(secret2, 32);
    printf("\n");
    //    }


    return 1;

}

static int ecdsa(void) {

    printf("\n\rTime ecdsa\n");
    uint32_t initialCountTotal = 0, finalCountTotal = 0, initialCountmakeKey = 0,
            initialCountSign = 0, finalCountmakeKeyTotal = 0, finalCountSignTotal = 0,
            initialCountVerify = 0, finalCountVerify = 0;

    uint32_t TotalECDSA = 0, TotalMakeKeys = 0, TotalSign = 0, TotalTotalSign = 0;

    int i;
    uint8_t private[32] = {0};
    uint8_t public[64] = {0};
    uint8_t hash[32] = {0};
    uint8_t sig[64] = {0};

    initialCountTotal = getCounter();

    for (i = 0; i < NUM_TESTS; i++) {
        initialCountmakeKey = getCounter();
        if (!uECC_make_key(public, private, uECC_secp256k1())) {
            printf("uECC_make_key() failed\n");
            return 1;
        }
        finalCountmakeKeyTotal = getCounter();
        memcpy(hash, public, sizeof (hash));

        initialCountSign = getCounter();
        if (!uECC_sign(private, hash, sizeof (hash), sig, uECC_secp256k1())) {
            printf("uECC_sign() failed\n");
            return 1;
        }
        finalCountSignTotal = getCounter();

        initialCountVerify = getCounter();
        if (!uECC_verify(public, hash, sizeof (hash), sig, uECC_secp256k1())) {
            printf("uECC_verify() failed\n");
            return 1;
        }
        finalCountVerify = getCounter();


        TotalMakeKeys += (finalCountmakeKeyTotal - initialCountmakeKey);
        TotalSign += (finalCountSignTotal - initialCountSign);
        TotalTotalSign += (finalCountVerify - initialCountVerify);
    }

    finalCountTotal = getCounter();
    TotalECDSA = (finalCountTotal - initialCountTotal);

    printf("\n\rTime TOTAL ECDSA: %d\n", TotalECDSA / NUM_TESTS);
    printf("\n\rTime TOTAL MAKEKEYS: %d\n", TotalMakeKeys / NUM_TESTS);
    printf("\n\rTime TOTAL SIGN MSG: %d\n", TotalSign / NUM_TESTS);
    printf("\n\rTime TOTAL VERIFY MSG: %d\n", TotalTotalSign / NUM_TESTS);



    printf("Private key  = ");
    vli_print(private, 32);
    printf("\n");
    printf("public key  = ");
    vli_print(public, 64);
    printf("\n");
    printf("SIG = ");
    vli_print(sig, 64);
    printf("\n");
    printf("HASH = ");
    vli_print(hash, 32);
    printf("\n");

    return 1;

}
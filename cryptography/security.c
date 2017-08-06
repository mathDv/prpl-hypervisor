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


#define DEBUG 1
#define NUM_TESTS 2

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
#endif

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
    hypercallsAuthorized[guestID][HCALL_READ_ADDRESS] = 0;
    return 0;

}
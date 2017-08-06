/*
Copyright (c) 2016, prpl Foundation

Permission to use, copy, modify, and/or distribute this software for any purpose with or without 
fee is hereby granted, provided that the above copyright notice and this permission notice appear 
in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE 
FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM 
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, 
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

This code was written by Carlos Moratelli at Embedded System Group (GSE) at PUCRS/Brazil.

 */

/* Simple UART and Blink Bare-metal application sample using virtualized IO. */

#include <arch.h>
#include <libc.h>
#include <hypercalls.h>
#include <guest_interrupts.h>
#include <platform.h>
#include <io.h>


volatile int32_t t2 = 0;

void irq_timer() {
    t2++;
}

int main() {


    //    get_guestid(); //0xB
//    eth_send_frame(2, 1); // 0x05
    //    eth_recv_frame(1); //0x06
    //    eth_mac(1);
    //    eth_watch();
    //    eth_mac(2);
    //    usb_polling();
        usb_control_send(1,2);//0xa
    //    writeio(0x1,1);
    //    readio(U2STA);
    //    writeio(TRISGCLR, 1 << 6);
    //    ipc_send(1,1,1);
    //    get_guestid();
    //    read_1k_data_flash(NULL);
    //    interrupt_register(irq_timer, GUEST_TIMER_INT);
    //    reenable_interrupt(1);

    while (1) {
        printf("\nBlink red LED! Total of %d timer ticks.", t2);

        /* Blink Led */
        TOGGLE_LED1;

        /* 1 second delay */
        udelay(1000000);
    }

    return 0;
}


/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   security.h
 * Author: matheus
 *
 * Created on August 10, 2016, 11:02 AM
 */
//#include <config.h>

#ifndef SECURITY_H
#define SECURITY_H

#ifdef __cplusplus
extern "C" {
#endif

    int isVmTrust(void);
    int identifyHypercalls(void);


#ifdef __cplusplus
}
#endif

#endif /* SECURITY_H */


# Begining of Java Card

## Overview

This project is realated to security and crypto 
The main applications using in this project are security and crypto

## Folder Structure

The src includes the packages which contains the interfaces and classes related to our application

The Java Card includes the vital APIs to develope the application

The scripts include the testbench to run the application by one command line

The README.md describes the detail of this project

## Enviroment and Installation

Install Eclipse 2020/03 or Lowwer version
Download dependencies (JDK - Java Development Kit, JCOP Tools (Java Card Open Platform) and Plugin License)
Set up the dependencies
Create a Java Card project then decrease the version of Java complier to 1.5

JCOP - sofware platform for developing the application on Java Card
Command-line interface: JCOP Shell - using to interact with applications running on Java Card 

## Applets

### ExamApp Applet

Getting started with Java Card Application
This applet is about how to gen a private key and derive the public key from the private one, then sig and verify a message using this key pair

### EccApp Applet

This is an upgrade version of ExamApplet
The private now is generated randomly 

### EccAes Applet

This is a trial version Applet to adapt the key exchange cryptography, is about how to gen a secret key, then encode and decode the message using this key and AES algorithm
But this version is only for learning, not for running

### ECDHApplet Applet

A inheritance of EccAes Applet
This is the main Applet which contains several version to update and complete the knowledge about Java Card Application

#### First version

The first version of this applet is about sending and receiving a cipher message through the secure channel using AES symmetric Key Cipher
The secret key first is initialed inside the Secure Channel without having partner public key
Then the incoming cipher message is decrypted to use for some caculation, then the result should be enrypted and send to the partner

#### Second version 

In this version, the secret key is derived from the reciever privateKey and sender publicKey
The exception SECURITY_STATUS_NOT_SATISFIED is added in the channel to inform that the share Key is not initail 

# Type of Smart Card

The applet required JavaCard 3.0.5 (with addition of KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY) or later.
The class byte of the APDU is not check since there are no conflicting INS code

The algorithms the card must support are at least:
* Cipher.ALG_AES_BLOCK_128_ECB_NOPAD
* Cipher.ALG_AES_CBC_ISO9797_M2
* KeyAgreement.ALG_EC_SVDP_DH_PLAIN
* KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY
* KeyPair.ALG_EC_FP (generation of 256-bit keys)
* MessageDigest.ALG_SHA_256
* MessageDigest.ALG_SHA_512
* RandomData.ALG_SECURE_RANDOM
* Signature.ALG_ECDSA_SHA_256



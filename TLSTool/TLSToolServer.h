/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information
    
    Abstract:
    Core of the s_server implementation.
 */

#import "TLSToolCommon.h"

NS_ASSUME_NONNULL_BEGIN

/*! An object that implements the tool's s_server command.
 *  \details To use this class, simply initialise it with a TLS server identity and 
 *  port and then call -run.  Before calling -run you can optionally configure 
 *  various parameters that modify its behaviour.
 */

@interface TLSToolServer : TLSToolCommon

/*! Initialises the object to server TLS connections with the specified identity from the specified port.
 *  \param serverIdentity The server identity to use; must not be NULL.
 *  \param port The port to listen on; must be in the range 1..65535, inclusive.
 *  \returns An initialised object.
 */

- (instancetype)initWithServerIdentify:(SecIdentityRef)serverIdentity port:(NSInteger)port NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

@property (atomic, assign, readonly ) SecIdentityRef    serverIdentity __attribute(( NSObject ));   ///< The server identity to use; set by the init method.
@property (atomic, assign, readonly ) NSInteger         port;                   ///< The port to listen on; set by the init method.

@property (atomic, copy,   readwrite, nullable) NSURL * autorespondContentURL;  ///< A file, or a directory containing files, to send clients.

/*! Runs the command, never returning.
 */

- (void)run __attribute__ ((noreturn));

@property (atomic, assign, readwrite) SSLAuthenticate   clientCertificateMode;          ///< Controls how the server authenticates clients.
@property (atomic, assign, readwrite) BOOL              disableClientTrustEvaluation;   ///< Set to YES to disable the server's trust evaluation of the client.
@property (atomic, copy,   readwrite) NSArray *         clientCertificateRoots;         ///< The certificate authorities expected to issue client our client certificates; an array of SecCertificateRefs.
// showCertificates and translateCRToCRLF properties inherited from TLSToolCommon

@end

NS_ASSUME_NONNULL_END


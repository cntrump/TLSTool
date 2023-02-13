/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information
    
    Abstract:
    Compatibility shim for OS X 10.10 / iOS 8 networking methods.
 */

#import "QNetworkAdditions.h"

@implementation QNetworkAdditions
 
+ (void)getStreamsToHostWithName:(NSString *)hostname 
    port:(NSInteger)port 
    inputStream:( NSInputStream  * __autoreleasing __nonnull * __nullable)inputStream 
    outputStream:(NSOutputStream * __autoreleasing __nonnull * __nullable)outputStream {
    CFReadStreamRef     readStream;
    CFWriteStreamRef    writeStream;
 
    assert(hostname != nil);
    assert( (port > 0) && (port < 65536) );
    assert( (inputStream != NULL) || (outputStream != NULL) );
 
    readStream = NULL;
    writeStream = NULL;
 
    CFStreamCreatePairWithSocketToHost(
        NULL,
        (__bridge CFStringRef) hostname,
        (UInt32) port,
        ((inputStream  != NULL) ? &readStream : NULL),
        ((outputStream != NULL) ? &writeStream : NULL)
    );
 
    if (inputStream != NULL) {
        *inputStream  = CFBridgingRelease(readStream);
    }
    if (outputStream != NULL) {
        *outputStream = CFBridgingRelease(writeStream);
    }
}

@end

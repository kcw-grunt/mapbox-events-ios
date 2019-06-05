#import <Cedar/Cedar.h>

#import "MMECertPin.h"
#import "MMEAPIClient.h"
#import "MMENSURLSessionWrapper.h"
#import "MMECommonEventData.h"
#import "MMEEvent.h"

using namespace Cedar::Matchers;
using namespace Cedar::Doubles;

/*
    Note:
 
    We test certificate pinning logic with a real network request
    because we cannot manually make a fake `NSURLAuthenticationChallenge` object.
 
    Once you want to create a fake `NSURLAuthenticationChallenge` object, the sub property `NSURLProtectionSpace`
    protectionSpace, will return a nil `SecTrustRef` serverTrust forever.
 
    It seems that is not as same as Apple's documentation:
    `Nil if the authenticationMethod is not NSURLAuthenticationMethodServerTrust`.
    See: https://developer.apple.com/documentation/foundation/nsurlprotectionspace/1409926-servertrust?language=objc
 
    This is why we can't simulate this behavior.
*/

@interface MMECertPin (CertPinTest)

@property (nonatomic) NSURLSessionAuthChallengeDisposition lastAuthChallengeDisposition;

@end

#pragma mark -

@interface MMENSURLSessionWrapper (CertPinTest)

@property (nonatomic) MMECertPin *certPin;

@end

#pragma mark -

@interface MMEAPIClient (CertPinTest)

@property (nonatomic) id<MMENSURLSessionWrapper> sessionWrapper;

@end

#pragma mark -

SPEC_BEGIN(MMEAPIClientCertPinSpec)

describe(@"MMEAPIClientCertPin", ^{

    it(@"should connect to events.mapbox.com without error", ^{
        MMENSURLSessionWrapper *sessionWrapper = [MMENSURLSessionWrapper new];
        NSURLRequest *eventsRequest = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://events.mapbox.com"]];
        NSLock *complete = [NSLock new];
        [complete lock];

        [sessionWrapper processRequest:eventsRequest completionHandler:
            ^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
            error should be_nil;
            [complete unlock];
        }];

        while (!complete.tryLock) { // wait a second to let the request complete
            [NSRunLoop.mainRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:1]];
        }
    });

    it(@"should connect to api.mapbox.com without error", ^{
        MMENSURLSessionWrapper *sessionWrapper = [MMENSURLSessionWrapper new];
        NSURLRequest *eventsRequest = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://api.mapbox.com"]];
        NSLock *complete = [NSLock new];
        [complete lock];

        [sessionWrapper processRequest:eventsRequest completionHandler:
            ^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
            error should be_nil;
            [complete unlock];
        }];

        while (!complete.tryLock) { // wait a second to let the request complete
            [NSRunLoop.mainRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:1]];
        }
    });

    it(@"should not connect to example.com without error", ^{
        MMENSURLSessionWrapper *sessionWrapper = [MMENSURLSessionWrapper new];
        NSURLRequest *eventsRequest = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://example.com"]];
        NSLock *complete = [NSLock new];
        [complete lock];

        [sessionWrapper processRequest:eventsRequest completionHandler:
            ^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
            error should be_nil;
            [complete unlock];
        }];

        while (!complete.tryLock) { // wait a second to let the request complete
            [NSRunLoop.mainRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:1]];
        }
    });

    it(@"should testGetConfigurationWithExcludedDomain", ^{
        MMEAPIClient *apiClient = [[MMEAPIClient alloc] initWithAccessToken:@"access-token"
                                                              userAgentBase:@"user-agent-base"
                                                             hostSDKVersion:@"host-sdk-1"];;
        __block MMENSURLSessionWrapper *sessionWrapper = [[MMENSURLSessionWrapper alloc] init];
        apiClient.sessionWrapper = sessionWrapper;
        NSLock *complete = [NSLock new];
        [complete lock];

        [apiClient getConfigurationWithCompletionHandler:^(NSError * _Nullable error, NSData * _Nullable data) {
            error should be_nil;
            sessionWrapper.certPin.lastAuthChallengeDisposition should equal(NSURLSessionAuthChallengePerformDefaultHandling);
            [complete unlock];
        }];

        while (!complete.tryLock) { // wait a second to let the request complete
            [NSRunLoop.mainRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:1]];
        }
    });
});

SPEC_END
